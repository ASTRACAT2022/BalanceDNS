package resolver

import (
	"context"
	"errors"
	"log"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"golang.org/x/sync/singleflight"
)

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	unbound    *unbound.Unbound
	workerPool *WorkerPool
	metrics    *metrics.Metrics
}

// NewUnboundResolver creates a new Unbound resolver instance.
func NewUnboundResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *Resolver {
	u := unbound.New()
	// It's recommended to configure a trust anchor for DNSSEC validation.
	// This could be from a file, or you can use the built-in one.
	// For simplicity, we'll try to load a standard root key file.
	if err := u.AddTaFile("/etc/unbound/root.key"); err != nil {
		log.Printf("Warning: could not load root trust anchor: %v. DNSSEC validation might not be secure.", err)
	}

	r := &Resolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
		unbound:    u,
		workerPool: NewWorkerPool(cfg.MaxWorkers),
		metrics:    m,
	}
	return r
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *Resolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *Resolver) GetConfig() *config.Config {
	return r.config
}

// Resolve performs a recursive DNS lookup for a given request.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	key := cache.Key(q)

	// Check the cache first.
	if cachedMsg, found, revalidate := r.cache.Get(key); found {
		log.Printf("Cache hit for %s (revalidate: %t)", q.Name, revalidate)
		cachedMsg.Id = req.Id

		if revalidate {
			r.metrics.IncrementCacheRevalidations()
			// Trigger a background revalidation using the worker pool
			go func() {
				if err := r.workerPool.Acquire(context.Background()); err != nil {
					log.Printf("Failed to acquire worker for revalidation: %v", err)
					return
				}
				defer r.workerPool.Release()

				ctx, cancel := context.WithTimeout(context.Background(), r.config.UpstreamTimeout)
				defer cancel()

				// Create a new request for revalidation to avoid race conditions on the original request object.
				revalidationReq := new(dns.Msg)
				revalidationReq.SetQuestion(q.Name, q.Qtype)
				revalidationReq.RecursionDesired = true
				if opt := req.IsEdns0(); opt != nil {
					revalidationReq.SetEdns0(opt.UDPSize(), opt.Do())
				}

				res, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.exchange(ctx, revalidationReq)
				})
				if err != nil {
					log.Printf("Background revalidation failed for %s: %v", q.Name, err)
					return
				}

				if msg, ok := res.(*dns.Msg); ok {
					r.cache.Set(key, msg, r.config.StaleWhileRevalidate)
					log.Printf("Successfully revalidated and updated cache for %s", q.Name)
				}
			}()
		}
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

// exchange is a wrapper around the unbound resolver's Resolve method.
func (r *Resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	startTime := time.Now()

	// Note: The Go wrapper for libunbound doesn't seem to support passing context for cancellation.
	result, err := r.unbound.Resolve(q.Name, q.Qtype, q.Qclass)
	latency := time.Since(startTime)

	// Always record latency
	r.metrics.RecordLatency(q.Name, latency)

	if err != nil {
		r.metrics.IncrementUnboundErrors()
		log.Printf("Unbound resolution error for %s: %v", q.Name, err)
		// When an error occurs, unbound does not return a message.
		// We'll construct a SERVFAIL to send back to the client.
		msg := new(dns.Msg)
		msg.SetRcode(req, dns.RcodeServerFailure)
		return msg, err
	}

	// Create a new response message from the result.
	// We need to manually construct the dns.Msg.
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = result.Rcode

	if result.Rcode == dns.RcodeNameError {
		r.metrics.RecordNXDOMAIN(q.Name)
	}

	// The unbound result gives us a flat list of RRs. We will add them
	// to the Answer section.
	if result.HaveData {
		msg.Answer = result.Rr
	}

	if result.Bogus {
		r.metrics.RecordDNSSECValidation("bogus")
		log.Printf("DNSSEC validation for %s resulted in BOGUS.", q.Name)
		// The test expects an error for bogus domains. We'll return a SERVFAIL
		// message that the calling handler can use, along with an error.
		msg.Rcode = dns.RcodeServerFailure
		return msg, errors.New("BOGUS: DNSSEC validation failed")
	} else if result.Secure {
		r.metrics.RecordDNSSECValidation("secure")
		log.Printf("DNSSEC validation for %s resulted in SECURE.", q.Name)
		msg.AuthenticatedData = true
	} else {
		r.metrics.RecordDNSSECValidation("insecure")
		log.Printf("DNSSEC validation for %s resulted in INSECURE.", q.Name)
		msg.AuthenticatedData = false
	}

	// Unlike the previous library, unbound doesn't return a fully-formed dns.Msg.
	// We've constructed it from the pieces in the result.
	return msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *Resolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}

// Close closes the resolver and frees resources.
func (r *Resolver) Close() {
	// Unbound doesn't need explicit cleanup in this implementation
}
