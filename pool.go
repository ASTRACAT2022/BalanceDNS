package resolver

import (
	"github.com/miekg/dns"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type NameserverPoolStatus uint8

const (
	PoolEmpty NameserverPoolStatus = iota
	PoolExpired
	PoolHasHostnamesButNoIpAddresses
	PrimedButNeedsEnhancing
	PoolPrimed
)

type nameserverPool struct {
	hostsWithoutAddresses []string

	ipv4      []exchanger
	ipv4Next  atomic.Uint32
	ipv4Count atomic.Uint32

	ipv6      []exchanger
	ipv6Next  atomic.Uint32
	ipv6Count atomic.Uint32

	updating sync.RWMutex
	enriched sync.Once

	expires atomic.Int64
}

func (pool *nameserverPool) hasIPv4() bool {
	return pool.countIPv4() > 0
}

func (pool *nameserverPool) hasIPv6() bool {
	return pool.countIPv6() > 0
}

func (pool *nameserverPool) countIPv4() uint32 {
	return pool.ipv4Count.Load()
}

func (pool *nameserverPool) countIPv6() uint32 {
	return pool.ipv6Count.Load()
}

func (pool *nameserverPool) getIPv4() exchanger {
	if pool.hasIPv4() {
		// Increments to the next server each time.
		// There's a race condition here, but the outcome isn't "important" enough to warrant locking.
		ipv4Next := pool.ipv4Next.Load() % pool.countIPv4()
		pool.ipv4Next.Store(ipv4Next + 1)

		var ex exchanger
		pool.updating.RLock()
		if int(ipv4Next) < len(pool.ipv4) {
			ex = pool.ipv4[ipv4Next]
		}
		pool.updating.RUnlock()
		return ex
	}
	return nil
}

func (pool *nameserverPool) getIPv6() exchanger {
	if pool.hasIPv6() {
		// Increments to the next server each time.
		// There's a race condition here, but the outcome isn't "important" enough to warrant locking.
		ipv6Next := pool.ipv6Next.Load() % pool.countIPv6()
		pool.ipv6Next.Store(ipv6Next + 1)

		var ex exchanger
		pool.updating.RLock()
		if int(ipv6Next) < len(pool.ipv6) {
			ex = pool.ipv6[ipv6Next]
		}
		pool.updating.RUnlock()
		return ex
	}
	return nil
}

//---

func (pool *nameserverPool) expired() bool {
	expires := pool.expires.Load()
	return expires > 0 && expires < time.Now().Unix()
}

func (pool *nameserverPool) status() NameserverPoolStatus {
	pool.updating.RLock()
	defer pool.updating.RUnlock()

	ipv4Count := len(pool.ipv4)
	ipv6Count := len(pool.ipv6)

	if ipv4Count == 0 && ipv6Count == 0 && len(pool.hostsWithoutAddresses) == 0 {
		return PoolEmpty
	}

	total := ipv4Count
	if IPv6Available() {
		total = total + ipv6Count
	}

	if total == 0 {
		return PoolHasHostnamesButNoIpAddresses
	}

	// If there are unknown addresses, and we have less than x IPs, then we want to enrich.
	if total < DesireNumberOfNameserversPerZone && len(pool.hostsWithoutAddresses) > 0 {
		return PrimedButNeedsEnhancing
	}

	return PoolPrimed
}

func newNameserverPool(nameservers []*dns.NS, extra []dns.RR) *nameserverPool {
	pool := &nameserverPool{}

	var ttl = MaxAllowedTTL
	pool.hostsWithoutAddresses = make([]string, 0, len(nameservers))

	for _, rr := range nameservers {
		hostname := canonicalName(rr.Ns)

		ttl = min(rr.Header().Ttl, ttl)

		//---

		a, aaaa, minTtlSeen := findAddressesForHostname(hostname, extra)

		if len(a) == 0 && len(aaaa) == 0 {
			pool.hostsWithoutAddresses = append(pool.hostsWithoutAddresses, hostname)
			continue
		}

		//---

		ttl = min(minTtlSeen, ttl)

		for _, addr := range a {
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}

	}

	pool.hostsWithoutAddresses = slices.Clip(pool.hostsWithoutAddresses)

	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	pool.expires.Store(expires.Unix())

	pool.updateIPCount()

	return pool
}

func (pool *nameserverPool) enrich(records []dns.RR) {
	if len(records) == 0 {
		return
	}

	pool.updating.Lock()
	defer pool.updating.Unlock()

	var ttl = MaxAllowedTTL
	hostnamesStillWithoutAddresses := make([]string, 0, len(pool.hostsWithoutAddresses))

	for _, hostname := range pool.hostsWithoutAddresses {

		a, aaaa, minTtlSeen := findAddressesForHostname(hostname, records)

		if len(a) == 0 && len(aaaa) == 0 {
			hostnamesStillWithoutAddresses = append(hostnamesStillWithoutAddresses, hostname)
			continue
		}

		//---

		ttl = min(minTtlSeen, ttl)

		for _, addr := range a {
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.A.String(),
			})
		}

		for _, addr := range aaaa {
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: addr.Header().Name,
				addr:     addr.AAAA.String(),
			})
		}
	}

	if pool.expires.Load() > 0 {
		expires := time.Now().Add(time.Duration(ttl) * time.Second)
		pool.expires.Store(expires.Unix())
	}

	//if !pool.expires.IsZero() {
	//	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	//	if expires.Before(pool.expires) {
	//		pool.expires = expires
	//	}
	//}

	pool.hostsWithoutAddresses = slices.Clip(hostnamesStillWithoutAddresses)

	pool.updateIPCount()
}

func (pool *nameserverPool) updateIPCount() {
	pool.ipv4Count.Store(uint32(len(pool.ipv4)))
	pool.ipv6Count.Store(uint32(len(pool.ipv6)))
}

func findAddressesForHostname(hostname string, records []dns.RR) ([]*dns.A, []*dns.AAAA, uint32) {
	a := make([]*dns.A, 0, len(records))
	aaaa := make([]*dns.AAAA, 0, len(records))

	var ttl = MaxAllowedTTL

	for _, rr := range records {
		if canonicalName(rr.Header().Name) != hostname {
			continue
		}
		switch addr := rr.(type) {
		case *dns.A:
			a = append(a, addr)
			ttl = min(rr.Header().Ttl, ttl)
		case *dns.AAAA:
			aaaa = append(aaaa, addr)
			ttl = min(rr.Header().Ttl, ttl)
		}
	}

	return a, aaaa, ttl
}
