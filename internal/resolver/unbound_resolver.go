//go:build unbound
// +build unbound

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

// revalidationTask represents a task for background revalidation.
type revalidationTask struct {
	key string
	req *dns.Msg
}

// Resolver is a recursive DNS resolver.
type Resolver struct {
	config             *config.Config
	cache              *cache.Cache
	sf                 singleflight.Group
	unboundPool        chan *unbound.Unbound
	metrics            *metrics.Metrics
	revalidationQueue  chan revalidationTask
	revalidationWg     sync.WaitGroup
	revalidationCancel context.CancelFunc
}

// NewUnboundResolver creates a new Unbound resolver instance.
func NewUnboundResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *Resolver {
	poolSize := cfg.MaxWorkers // Use MaxWorkers as the pool size
	if poolSize <= 0 {
		poolSize = 10 // Default pool size
	}
	pool := make(chan *unbound.Unbound, poolSize)
	for i := 0; i < poolSize; i++ {
		u := unbound.New()
		if err := u.AddTaFile("/etc/unbound/root.key"); err != nil {
			log.Printf("Warning: could not load root trust anchor for pool instance %d: %v. DNSSEC validation might not be secure.", i, err)
		}
		pool <- u
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &Resolver{
		config:             cfg,
		cache:              c,
		sf:                 singleflight.Group{},
		unboundPool:        pool,
		metrics:            m,
		revalidationQueue:  make(chan revalidationTask, cfg.MaxWorkers*2),
		revalidationCancel: cancel,
	}

	r.startRevalidationWorkers(ctx, cfg.MaxWorkers)
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
			// Create a new request for revalidation to avoid race conditions on the original request object.
			revalidationReq := new(dns.Msg)
			revalidationReq.SetQuestion(q.Name, q.Qtype)
			revalidationReq.RecursionDesired = true
			if opt := req.IsEdns0(); opt != nil {
				revalidationReq.SetEdns0(opt.UDPSize(), opt.Do())
			}

			// Send the revalidation task to the queue without blocking the current request.
			select {
			case r.revalidationQueue <- revalidationTask{key: key, req: revalidationReq}:
				log.Printf("Queued revalidation for %s", q.Name)
			default:
				log.Printf("Revalidation queue is full for %s. Skipping.", q.Name)
			}
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

	// Get an unbound instance from the pool
	u := <-r.unboundPool
	defer func() { r.unboundPool <- u }()

	// Note: The Go wrapper for libunbound doesn't seem to support passing context for cancellation.
	result, err := u.Resolve(q.Name, q.Qtype, q.Qclass)
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

	// Sort RRs into correct sections.
	if result.HaveData {
		nsRecords := make(map[string]bool)
		for _, rr := range result.Rr {
			if ns, ok := rr.(*dns.NS); ok {
				nsRecords[ns.Ns] = true
			}
		}

		for _, rr := range result.Rr {
			hdr := rr.Header()
			isGlue := false
			if hdr.Rrtype == dns.TypeA || hdr.Rrtype == dns.TypeAAAA {
				if _, ok := nsRecords[hdr.Name]; ok {
					isGlue = true
				}
			}

			switch {
			case hdr.Rrtype == dns.TypeSOA || hdr.Rrtype == dns.TypeNS:
				msg.Ns = append(msg.Ns, rr)
			case isGlue:
				msg.Extra = append(msg.Extra, rr)
			default:
				msg.Answer = append(msg.Answer, rr)
			}
		}
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

// startRevalidationWorkers starts a pool of workers to handle background revalidations.
func (r *Resolver) startRevalidationWorkers(ctx context.Context, numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		r.revalidationWg.Add(1)
		go func() {
			defer r.revalidationWg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-r.revalidationQueue:
					if !ok {
						return
					}
					q := task.req.Question[0]
					log.Printf("Revalidating %s", q.Name)
					res, err, _ := r.sf.Do(task.key+"-revalidate", func() (interface{}, error) {
						return r.exchange(ctx, task.req)
					})
					if err != nil {
						log.Printf("Background revalidation failed for %s: %v", q.Name, err)
						continue
					}
					if msg, ok := res.(*dns.Msg); ok {
						r.cache.Set(task.key, msg, r.config.StaleWhileRevalidate)
						log.Printf("Successfully revalidated and updated cache for %s", q.Name)
					}
				}
			}
		}()
	}
}

// Close closes the resolver and frees resources.
func (r *Resolver) Close() {
	r.revalidationCancel()
	close(r.revalidationQueue)
	r.revalidationWg.Wait()

	// Drain the pool and close unbound instances
	close(r.unboundPool)
	for u := range r.unboundPool {
		u.Destroy()
	}
}
