package main

import (
	"fmt"
	"log"
	"strings"

	"dns-resolver/internal/config"
	"dns-resolver/internal/recursor"
	"github.com/miekg/dns"
)

type runtimeResolver interface {
	Resolve(question dns.Question) (*dns.Msg, error)
	Reload(rootAnchorPath string) error
	ClearCache(rootAnchorPath string) error
	Close()
	WorkerCount() int
}

func newRuntimeResolver(cfg *config.Config) (runtimeResolver, error) {
	resolverType := strings.ToLower(strings.TrimSpace(cfg.ResolverType))
	if resolverType == "" {
		resolverType = "recursor"
	}

	switch resolverType {
	case "recursor", "knot":
		log.Println("Initializing built-in recursive resolver...")
		r, err := recursor.NewResolverWithOptions(recursor.Options{
			WorkerCount:      cfg.ResolverWorkers,
			QueryTimeout:     cfg.UpstreamTimeout,
			ResolveTimeout:   cfg.RequestTimeout,
			RootServers:      cfg.RecursorRootServers,
			CacheEntries:     cfg.RecursorCacheEntries,
			CacheMinTTL:      cfg.RecursorCacheMinTTL,
			CacheMaxTTL:      cfg.RecursorCacheMaxTTL,
			ValidateDNSSEC:   cfg.DNSSECValidate,
			DNSSECFailClosed: cfg.DNSSECFailClosed,
			DNSSECTrustDS:    cfg.DNSSECTrustAnchors,
		})
		if err != nil {
			return nil, err
		}
		log.Printf(
			"Built-in recursion configured: workers=%d query-timeout=%s resolve-timeout=%s cache-entries=%d cache-min-ttl=%s cache-max-ttl=%s dnssec-validate=%v dnssec-fail-closed=%v",
			r.WorkerCount(),
			cfg.UpstreamTimeout,
			cfg.RequestTimeout,
			cfg.RecursorCacheEntries,
			cfg.RecursorCacheMinTTL,
			cfg.RecursorCacheMaxTTL,
			cfg.DNSSECValidate,
			cfg.DNSSECFailClosed,
		)
		return r, nil
	case "unbound":
		log.Println("Initializing Unbound recursive resolver (miekg/unbound)...")
		r, err := newUnboundResolver(cfg)
		if err != nil {
			return nil, err
		}
		log.Printf(
			"Unbound recursion configured: workers=%d query-timeout=%s resolve-timeout=%s root-anchor=%s msg-cache=%s rrset-cache=%s key-cache=%s prefetch=%v serve-expired=%v disable-cache=%v",
			r.WorkerCount(),
			cfg.UpstreamTimeout,
			cfg.RequestTimeout,
			cfg.RootAnchorPath,
			cfg.UnboundMsgCacheSize,
			cfg.UnboundRRsetCacheSize,
			cfg.UnboundKeyCacheSize,
			cfg.UnboundPrefetch,
			cfg.UnboundServeExpired,
			cfg.UnboundDisableCache,
		)
		return r, nil
	default:
		return nil, fmt.Errorf("unsupported resolver_type=%q (supported: recursor, knot, unbound)", cfg.ResolverType)
	}
}
