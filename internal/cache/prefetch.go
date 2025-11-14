package cache

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
)

// PrefetchManager handles proactive caching of related records
type PrefetchManager struct {
	mu        sync.RWMutex
	cache     *Cache
	metrics   *metrics.Metrics
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewPrefetchManager creates a new prefetch manager
func NewPrefetchManager(cache *Cache, metrics *metrics.Metrics) *PrefetchManager {
	ctx, cancel := context.WithCancel(context.Background())
	pm := &PrefetchManager{
		cache:   cache,
		metrics: metrics,
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start a background goroutine to process prefetch requests
	go pm.runPrefetchProcessor()
	
	return pm
}

// Close stops the prefetch manager
func (pm *PrefetchManager) Close() {
	if pm.cancel != nil {
		pm.cancel()
	}
}

// PrefetchRelatedRecords initiates prefetching of related records for a domain
func (pm *PrefetchManager) PrefetchRelatedRecords(domain string, qType uint16) {
	// Only prefetch for A and AAAA records if the original request was for those types
	if qType != dns.TypeA && qType != dns.TypeAAAA {
		return
	}

	// Check if we've recently tried to prefetch for this domain
	if pm.shouldSkipPrefetch(domain) {
		return
	}

	// Prefetch common related records: AAAA for A requests, and vice versa
	go func() {
		domain = strings.ToLower(dns.Fqdn(domain))
		
		if qType == dns.TypeA {
			// Prefetch AAAA for the same domain
			pm.prefetchRecord(domain, dns.TypeAAAA)
		} else if qType == dns.TypeAAAA {
			// Prefetch A for the same domain
			pm.prefetchRecord(domain, dns.TypeA)
		}
		
		// Prefetch NS records for the domain
		pm.prefetchRecord(domain, dns.TypeNS)
		
		// Prefetch SOA records for the domain
		pm.prefetchRecord(domain, dns.TypeSOA)
	}()
}

// prefetchRecord attempts to prefetch a specific record type for a domain
func (pm *PrefetchManager) prefetchRecord(domain string, qType uint16) {
	// Create a minimal request
	req := new(dns.Msg)
	req.SetQuestion(domain, qType)
	req.RecursionDesired = true
	req.SetEdns0(4096, true)

	// Attempt to resolve and cache the record
	if resolver := pm.cache.resolver; resolver != nil {
		ctx, cancel := context.WithTimeout(pm.ctx, 2*time.Second) // Short timeout for prefetch
		defer cancel()
		
		// Perform the lookup without cache to get fresh data
		resp, err := resolver.LookupWithoutCache(ctx, req)
		if err != nil {
			log.Printf("Failed to prefetch %s record for %s: %v", dns.TypeToString[qType], domain, err)
			return
		}

		// Cache the response if it's valid
		if resp != nil && resp.Rcode == dns.RcodeSuccess {
			packedMsg, err := resp.Pack()
			if err != nil {
				log.Printf("Failed to pack prefetched response for %s: %v", domain, err)
				return
			}
			key := Key(dns.Question{Name: domain, Qtype: qType, Qclass: dns.ClassINET})
			pm.cache.setInMemory(key, packedMsg, req.Question[0], time.Minute, time.Now().Add(time.Minute*5))
			pm.metrics.IncrementPrefetches()
			log.Printf("Successfully prefetched %s record for %s", dns.TypeToString[qType], domain)
		}
	}
}

// shouldSkipPrefetch determines if we should skip prefetching for a domain
func (pm *PrefetchManager) shouldSkipPrefetch(domain string) bool {
	// Basic implementation to prevent excessive prefetching
	// In a production system, you might track recent prefetch attempts
	return false
}

// runPrefetchProcessor runs periodically to maintain prefetch operations
func (pm *PrefetchManager) runPrefetchProcessor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			// Process any scheduled prefetch operations
			// For now, this is just a placeholder; actual prefetching happens immediately
		}
	}
}

// PrefetchForResponse analyzes a DNS response and prefetches related records
func (pm *PrefetchManager) PrefetchForResponse(resp *dns.Msg) {
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return
	}

	// Look for domains in the response that we might want to prefetch related records for
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			// Prefetch AAAA for domains that have A records
			pm.PrefetchRelatedRecords(a.Hdr.Name, dns.TypeA)
		} else if aaaa, ok := rr.(*dns.AAAA); ok {
			// Prefetch A for domains that have AAAA records
			pm.PrefetchRelatedRecords(aaaa.Hdr.Name, dns.TypeAAAA)
		} else if cname, ok := rr.(*dns.CNAME); ok {
			// Prefetch the target of CNAME records
			pm.PrefetchRelatedRecords(cname.Target, dns.TypeA)
			pm.PrefetchRelatedRecords(cname.Target, dns.TypeAAAA)
		} else if mx, ok := rr.(*dns.MX); ok {
			// Prefetch A/AAAA records for mail server domains
			pm.PrefetchRelatedRecords(mx.Mx, dns.TypeA)
			pm.PrefetchRelatedRecords(mx.Mx, dns.TypeAAAA)
		} else if ns, ok := rr.(*dns.NS); ok {
			// Prefetch A/AAAA records for nameserver domains
			pm.PrefetchRelatedRecords(ns.Ns, dns.TypeA)
			pm.PrefetchRelatedRecords(ns.Ns, dns.TypeAAAA)
		}
	}

	// Also prefetch records in the additional section
	for _, rr := range resp.Extra {
		if a, ok := rr.(*dns.A); ok {
			pm.PrefetchRelatedRecords(a.Hdr.Name, dns.TypeA)
		} else if aaaa, ok := rr.(*dns.AAAA); ok {
			pm.PrefetchRelatedRecords(aaaa.Hdr.Name, dns.TypeAAAA)
		}
	}
}