package resolver

import (
	"context"
	"log"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"errors"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
	"github.com/nsmithuk/resolver/dnssec"
	"golang.org/x/sync/singleflight"
)

// DnslibResolver is a recursive DNS resolver using dnslib.
type DnslibResolver struct {
	config      *config.Config
	cache       *cache.Cache
	sf          singleflight.Group
	metrics     *metrics.Metrics
	dnslib      *resolver.Resolver
}

// NewDnslibResolver creates a new DnslibResolver instance.
func NewDnslibResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *DnslibResolver {
	return &DnslibResolver{
		config:  cfg,
		cache:   c,
		sf:      singleflight.Group{},
		metrics: m,
		dnslib:  resolver.NewResolver(),
	}
}

// Resolve performs a recursive DNS lookup for a given request.
func (r *DnslibResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	key := cache.Key(q)

	// Check the cache first.
	if cachedMsg, found, _ := r.cache.Get(key); found {
		log.Printf("Cache hit for %s", q.Name)
		cachedMsg.Id = req.Id
		return cachedMsg, nil
	}

	// Use singleflight to ensure only one lookup for a given question is in flight at a time.
	res, err, _ := r.sf.Do(key, func() (interface{}, error) {
		return r.exchange(ctx, req)
	})

	if err != nil {
		return nil, err
	}

	msg := res.(*dns.Msg)
	msg.Id = req.Id

	// Cache the response
	r.cache.Set(key, msg, r.config.StaleWhileRevalidate)

	return msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *DnslibResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}

// exchange is a wrapper around the dnslib resolver's Exchange method.
func (r *DnslibResolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]

	// dnslib doesn't have a direct context cancellation mechanism in the same way as other libraries.
	// We will rely on the context deadline or timeout if it's set.
	result := r.dnslib.Exchange(ctx, req)

	if result.Err != nil {
		log.Printf("dnslib resolution error for %s: %v", q.Name, result.Err)
		// Construct a SERVFAIL to send back to the client.
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, result.Err
	}

	if result.Msg.Rcode == dns.RcodeNameError {
		r.metrics.RecordNXDOMAIN(q.Name)
	}

	if result.Auth == dnssec.Bogus {
		r.metrics.RecordDNSSECValidation("bogus")
		log.Printf("DNSSEC validation for %s resulted in BOGUS.", q.Name)
		result.Msg.Rcode = dns.RcodeServerFailure
		return result.Msg, errors.New("BOGUS: DNSSEC validation failed")
	} else if result.Auth == dnssec.Secure {
		r.metrics.RecordDNSSECValidation("secure")
		log.Printf("DNSSEC validation for %s resulted in SECURE.", q.Name)
		result.Msg.AuthenticatedData = true
	} else {
		r.metrics.RecordDNSSECValidation("insecure")
		log.Printf("DNSSEC validation for %s resulted in INSECURE.", q.Name)
		result.Msg.AuthenticatedData = false
	}


	return result.Msg, nil
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *DnslibResolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *DnslibResolver) GetConfig() *config.Config {
	return r.config
}

// Close closes the resolver and frees resources.
func (r *DnslibResolver) Close() {
	// No resources to free for dnslib
}
