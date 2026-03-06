//go:build cgo && unbound

package main

import (
	"dns-resolver/internal/config"
	"dns-resolver/internal/unbound"
)

func newUnboundResolver(cfg *config.Config) (runtimeResolver, error) {
	return unbound.NewResolverWithOptions(unbound.Options{
		RootAnchorPath: cfg.RootAnchorPath,
		WorkerCount:    cfg.ResolverWorkers,
		MsgCacheSize:   cfg.UnboundMsgCacheSize,
		RRsetCacheSize: cfg.UnboundRRsetCacheSize,
		KeyCacheSize:   cfg.UnboundKeyCacheSize,
		Prefetch:       cfg.UnboundPrefetch,
		ServeExpired:   cfg.UnboundServeExpired,
	})
}
