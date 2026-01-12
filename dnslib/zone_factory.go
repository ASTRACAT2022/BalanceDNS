package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"time"
)

func createZone(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger) (zone, error) {
	name = dns.CanonicalName(name)
	parent = dns.CanonicalName(parent)

	if name == parent || !dns.IsSubDomain(parent, name) {
		return nil, fmt.Errorf("%w: the new zone name [%s] must be a subdomain of the parent [%s]", ErrFailedCreatingZoneAndPool, name, parent)
	}

	//---

	pool := newNameserverPool(nameservers, extra)

	switch pool.status() {
	case PrimedButNeedsEnhancing:
		if !LazyEnrichment {
			go func() {
				enrichPool(ctx, name, pool, exchanger)
			}()
		}
	case PoolPrimed:
		// Happy days - nothing to do
	case PoolHasHostnamesButNoIpAddresses:
		err := enrichPool(ctx, name, pool, exchanger)
		if err != nil {
			return nil, err
		}
	default:
		// Covers PoolEmpty
		return nil, fmt.Errorf("%w for [%s]: the nameserver pool is empty and we have no hostnames to enrich", ErrFailedCreatingZoneAndPool, name)
	}

	z := &zoneImpl{
		zoneName:   name,
		parentName: parent,
		pool:       pool,
	}

	Debug(fmt.Sprintf("new zone created [%s]", name))

	// TODO: It would be good if we validated, via DNSSEC, nameserver details. Perhaps we could go do this.
	// And use low TTLs until it's done.

	return z, nil
}

func enrichPool(ctx context.Context, zoneName string, pool *nameserverPool, exchanger exchanger) error {
	if len(pool.hostsWithoutAddresses) == 0 {
		return fmt.Errorf("%w [%s]: the nameserver pool is empty so we have no hostnames to enrich", ErrFailedEnrichingPool, zoneName)
	}

	hosts := pool.hostsWithoutAddresses

	if len(hosts) > DesireNumberOfNameserversPerZone {
		hosts = hosts[:DesireNumberOfNameserversPerZone]
	}

	types := make([]uint16, 0, 2)
	types = append(types, dns.TypeA)
	if IPv6Available() {
		types = append(types, dns.TypeAAAA)
	}

	//---

	done := make(chan bool)
	go func() {
		doneCalled := false
		for _, t := range types {
			for _, domain := range hosts {
				qmsg := new(dns.Msg)
				qmsg.SetQuestion(dns.Fqdn(domain), t)

				response := exchanger.exchange(ctx, qmsg)
				if !response.HasError() && !response.IsEmpty() && len(response.Msg.Answer) > 0 {
					// enrich if the response is good.
					pool.enrich(response.Msg.Answer)
					if !doneCalled {
						done <- true
						doneCalled = true
					}
				}
			}
		}
	}()

	select {
	case <-done:
		switch pool.status() {
		case PoolPrimed:
		case PrimedButNeedsEnhancing:
		default:
			return fmt.Errorf("%w [%s]: the nameserver pool still not primed after enrichment", ErrFailedEnrichingPool, zoneName)
		}
	case <-time.After(3 * time.Second):
		return fmt.Errorf("%w [%s]: enrichment timeout", ErrFailedEnrichingPool, zoneName)
	}

	Debug(fmt.Sprintf("zone pool enriched for [%s]", zoneName))

	return nil
}
