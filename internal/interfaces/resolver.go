package interfaces

import (
	"context"

	"dns-resolver/internal/config"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// CacheResolver defines the methods that the cache needs from the resolver.
type CacheResolver interface {
	GetSingleflightGroup() *singleflight.Group
	GetConfig() *config.Config
	LookupWithoutCache(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}
