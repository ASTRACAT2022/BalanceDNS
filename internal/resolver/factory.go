package resolver

import (
	"context"
	"fmt"
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
	// ResolverTypeDnslib uses dnslib for DNS resolution
	ResolverTypeDnslib ResolverType = "dnslib"
	// ResolverTypeGoDNS uses the pure Go implementation
	ResolverTypeGoDNS  ResolverType = "godns"
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
	case ResolverTypeDnslib:
		log.Println("Creating Dnslib resolver")
		return NewDnslibResolver(cfg, c, m), nil
	case ResolverTypeGoDNS:
		log.Println("Creating GoDNS resolver")
		return NewGoDNSResolver(cfg, c, m), nil
	default:
		return nil, fmt.Errorf("unknown resolver type: %s", resolverType)
	}
}
