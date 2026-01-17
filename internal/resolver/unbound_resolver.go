//go:build exclude

package resolver

import (
	"context"
	"fmt"
	"log"
	"sync"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"golang.org/x/sync/singleflight"
)

// UnboundResolver implements ResolverInterface using miekg/unbound.
type UnboundResolver struct {
	config  *config.Config
	cache   *cache.Cache
	sf      singleflight.Group
	ub      *unbound.Unbound
	metrics *metrics.Metrics
	mu      sync.Mutex
}

// NewUnboundResolver creates a new Unbound resolver instance.
func NewUnboundResolver(cfg *config.Config, c *cache.Cache, m *metrics.Metrics) *UnboundResolver {
	u := unbound.New()

	// Configure Unbound
	if err := u.AddTaFile(cfg.RootAnchorPath); err != nil {
		log.Printf("Warning: Failed to add root anchor file %s: %v", cfg.RootAnchorPath, err)
	}

	// Enable DNSSEC
	if err := u.SetOption("validator", "yes"); err != nil {
		log.Printf("Warning: Failed to enable validator: %v", err)
	}

	return &UnboundResolver{
		config:  cfg,
		cache:   c,
		ub:      u,
		metrics: m,
	}
}

// Resolve performs a recursive DNS lookup using Unbound.
func (r *UnboundResolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]
	key := cache.Key(q)

	// Check cache first
	if msg, found, _ := r.cache.Get(key); found {
		if msg != nil {
			msg.Id = req.Id
			return msg, nil
		}
	}

	// Use singleflight
	res, err, _ := r.sf.Do(key, func() (interface{}, error) {
		return r.LookupWithoutCache(ctx, req)
	})

	if err != nil {
		return nil, err
	}

	msg := res.(*dns.Msg)
	msg.Id = req.Id

	// Cache the result
	r.cache.Set(key, msg, r.config.StaleWhileRevalidate)

	return msg, nil
}

// LookupWithoutCache performs the lookup using Unbound without checking cache.
func (r *UnboundResolver) LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := req.Question[0]

	// Perform Unbound resolution
	result, err := r.ub.Resolve(q.Name, q.Qtype, q.Qclass)
	if err != nil {
		return nil, fmt.Errorf("unbound resolution failed: %v", err)
	}

	if result.AnswerPacket != nil {
		// AnswerPacket is already a *dns.Msg structure in the Go wrapper we are using
		msg := result.AnswerPacket
		msg.Id = req.Id

		// DNSSEC status check - if secure, mark AD bit
		if result.Secure {
			msg.AuthenticatedData = true
		}

		return msg, nil
	}

	// If no AnswerPacket, construct a basic response (fallback)
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = result.Rcode

	return msg, nil
}

// GetSingleflightGroup returns the singleflight group.
func (r *UnboundResolver) GetSingleflightGroup() *singleflight.Group {
	return &r.sf
}

// GetConfig returns the configuration.
func (r *UnboundResolver) GetConfig() *config.Config {
	return r.config
}

// Close destroys the Unbound instance.
func (r *UnboundResolver) Close() {
	r.ub.Destroy()
}
