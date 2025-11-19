package resolver

import (
	"context"
	"github.com/miekg/dns"
	"strings"
)

type Resolver struct {
	zones zoneStore
	funcs resolverFunctions
}

// The core, top level, resolving functions. They're defined as variables to aid overriding them for testing.
type resolverFunctions struct {
	resolveLabel         func(ctx context.Context, d *domain, z zone, qmsg *dns.Msg, auth *authenticator) (zone, *Response)
	checkForMissingZones func(ctx context.Context, d *domain, z zone, rmsg *dns.Msg, auth *authenticator) zone
	createZone           func(ctx context.Context, name, parent string, nameservers []*dns.NS, extra []dns.RR, exchanger exchanger) (zone, error)
	finaliseResponse     func(ctx context.Context, auth *authenticator, qmsg *dns.Msg, response *Response) *Response
	processDelegation    func(ctx context.Context, z zone, rmsg *dns.Msg) (zone, *Response)
	cname                func(ctx context.Context, qmsg *dns.Msg, r *Response, exchanger exchanger) error
	getExchanger         func() exchanger
}

func NewResolver() *Resolver {
	pool, err := buildRootServerPool()
	if err != nil {
		// Everything is technically static at this point.
		panic(err)
	}

	z := new(zones)
	z.add(&zoneImpl{
		zoneName: ".",
		pool:     pool,
	})

	resolver := &Resolver{
		zones: z,
	}

	// When not testing, we point to the concrete instances of the functions.
	resolver.funcs = resolverFunctions{
		resolveLabel:         resolver.resolveLabel,
		checkForMissingZones: resolver.checkForMissingZones,
		createZone:           createZone,
		finaliseResponse:     resolver.finaliseResponse,
		processDelegation:    resolver.processDelegation,
		cname:                cname,
		getExchanger:         resolver.getExchanger,
	}

	return resolver
}

func (resolver *Resolver) getExchanger() exchanger {
	return resolver
}

// CountZones metrics gathering.
func (resolver *Resolver) CountZones() int {
	return resolver.zones.count()
}

//-----------------------------------------------------------------------------

func buildRootServerPool() (*nameserverPool, error) {
	zp := dns.NewZoneParser(strings.NewReader(rootZone), ".", "local")

	pool := &nameserverPool{hostsWithoutAddresses: make([]string, 0)}

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr := rr.(type) {
		case *dns.A:
			pool.ipv4 = append(pool.ipv4, &nameserver{
				hostname: canonicalName(rr.Header().Name),
				addr:     rr.A.String(),
			})
		case *dns.AAAA:
			pool.ipv6 = append(pool.ipv6, &nameserver{
				hostname: canonicalName(rr.Header().Name),
				addr:     rr.AAAA.String(),
			})
		default:
			// Continue
		}
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}

	pool.updateIPCount()

	return pool, nil
}
