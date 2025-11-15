package resolver

import (
	"context"
	"log"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// ResolverType represents the type of resolver to use.
type ResolverType string

const (
	// ResolverTypeUnbound uses libunbound for DNS resolution
	ResolverTypeUnbound ResolverType = "unbound"
	// ResolverTypeGoDNS uses pure Go DNS implementation
	ResolverTypeGoDNS ResolverType = "godns"
)

// ResolverInterface defines the common interface for all resolvers.
type ResolverInterface interface {
	Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	GetSingleflightGroup() *singleflight.Group
	GetConfig() *config.Config
	Close()
}

// NewResolver creates a new resolver instance based on the specified type.
func NewResolver(resolverType ResolverType, cfg *config.Config, c *cache.Cache, m *metrics.Metrics) (ResolverInterface, error) {
	switch resolverType {
	case ResolverTypeUnbound:
		log.Println("Creating Unbound resolver")
		return NewUnboundResolver(cfg, c, m), nil
	case ResolverTypeGoDNS:
		log.Println("Creating GoDNS resolver")
		return NewGoDNSResolver(cfg, c, m), nil
	default:
		log.Printf("Unknown resolver type: %s, defaulting to GoDNS", string(resolverType))
		return NewGoDNSResolver(cfg, c, m), nil
	}
}