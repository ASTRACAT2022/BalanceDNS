package resolver

import (
	"context"
	"dns-resolver/internal/pool"
	"log"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// GoDNSResolver is a pure Go recursive DNS resolver.
type GoDNSResolver struct {
	config     *config.Config
	cache      *cache.Cache
	sf         singleflight.Group
	workerPool *WorkerPool
	metrics    *metrics.Metrics
}

// NewGoDNSResolver creates a new GoDNS resolver instance.
func NewGoDNSResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *GoDNSResolver {
	return &GoDNSResolver{
		config:     cfg,
		cache:      c,
		sf:         singleflight.Group{},
		workerPool: NewWorkerPool(cfg.MaxWorkers),
		metrics:    m,
	}
}

// GetSingleflightGroup returns the singleflight.Group instance.
func (r *GoDNSResolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the resolver's configuration.
func (r *GoDNSResolver) GetConfig() *config.Config {
	return r.config
}

// Resolve performs a recursive DNS lookup for a given request.
func (r *GoDNSResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
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

				// Create a new request for revalidation to avoid race conditions on the original request object.
				revalidationReq := pool.GetMsg()
				defer pool.PutMsg(revalidationReq)
				revalidationReq.SetQuestion(q.Name, q.Qtype)
				revalidationReq.RecursionDesired = true
				if opt := req.IsEdns0(); opt != nil {
					revalidationReq.SetEdns0(opt.UDPSize(), opt.Do())
				}

				res, err, _ := r.sf.Do(key+"-revalidate", func() (interface{}, error) {
					return r.exchange(context.Background(), revalidationReq)
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

// exchange performs a DNS lookup against an upstream resolver.
func (r *GoDNSResolver) exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	// For simplicity, we'll use a hardcoded upstream resolver.
	// In a real-world scenario, you would want to use a list of resolvers.
	msg, _, err := c.ExchangeContext(ctx, req, "8.8.8.8:53")
	return msg, err
}

// LookupWithoutCache performs a recursive DNS lookup for a given request, bypassing the cache.
func (r *GoDNSResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.exchange(ctx, req)
}

// Close closes the resolver and frees resources.
func (r *GoDNSResolver) Close() {
	// No-op for GoDNSResolver
}
