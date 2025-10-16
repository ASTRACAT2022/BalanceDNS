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
	"golang.org/x/sync/singleflight"
)

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	dnsClient  *dns.Client
	workerPool *WorkerPool
	metrics    *metrics.Metrics
}

// NewResolver creates a new resolver instance.
func NewResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *Resolver {
	r := &Resolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
		dnsClient:  &dns.Client{Timeout: cfg.UpstreamTimeout},
		workerPool: NewWorkerPool(cfg.MaxWorkers),
		metrics:    m,
	}
	c.SetResolver(r)
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
					r.cache.Set(key, msg, r.config.StaleWhileRevalidate, r.config.PrefetchInterval)
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
	r.cache.Set(key, msg, r.config.StaleWhileRevalidate, r.config.PrefetchInterval)

	return msg, nil
}

// exchange sends a DNS query to the upstream resolver (Knot Resolver).
func (r *Resolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	startTime := time.Now()

	msg, _, err := r.dnsClient.ExchangeContext(ctx, req, r.config.KnotResolverAddr)
	latency := time.Since(startTime)

	// Always record latency
	r.metrics.RecordLatency(q.Name, latency)

    if err != nil {
        r.metrics.IncrementUpstreamErrors()
		log.Printf("Upstream exchange error for %s: %v", q.Name, err)
		// Create a SERVFAIL response on error.
		failMsg := new(dns.Msg)
		failMsg.SetRcode(req, dns.RcodeServerFailure)
		return failMsg, err
	}

	if msg.Rcode == dns.RcodeNameError {
		r.metrics.RecordNXDOMAIN(q.Name)
	}

	// Check for SERVFAIL, which can indicate a BOGUS response from a validating resolver.
	if msg.Rcode == dns.RcodeServerFailure {
		r.metrics.RecordDNSSECValidation("bogus")
		log.Printf("DNSSEC validation for %s resulted in BOGUS (SERVFAIL).", q.Name)
		return msg, errors.New("BOGUS: upstream resolver returned SERVFAIL")
	}

	if msg.AuthenticatedData {
		r.metrics.RecordDNSSECValidation("secure")
		log.Printf("DNSSEC validation for %s resulted in SECURE.", q.Name)
	} else {
		r.metrics.RecordDNSSECValidation("insecure")
		log.Printf("DNSSEC validation for %s resulted in INSECURE.", q.Name)
	}

	return msg, nil
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *Resolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}
