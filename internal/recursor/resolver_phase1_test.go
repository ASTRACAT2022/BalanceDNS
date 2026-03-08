package recursor

import (
	"testing"
	"time"
)

func TestOrderServersPrefersLowerScore(t *testing.T) {
	r := &Resolver{
		opts: withDefaultOptions(Options{QueryTimeout: 200 * time.Millisecond}),
		nsStats: map[string]nsServerStats{
			normalizeServerAddr("192.0.2.1"): {srtt: 50 * time.Millisecond, failures: 0},
			normalizeServerAddr("192.0.2.2"): {srtt: 10 * time.Millisecond, failures: 0},
			normalizeServerAddr("192.0.2.3"): {srtt: 5 * time.Millisecond, failures: 5},
		},
	}

	ordered := r.orderServers([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"})
	if len(ordered) != 3 {
		t.Fatalf("unexpected len: %d", len(ordered))
	}

	if got, want := ordered[0], "192.0.2.2"; got != want {
		t.Fatalf("first server=%s want=%s", got, want)
	}
}

func TestNSHostCachePrefetchTrigger(t *testing.T) {
	r := &Resolver{
		opts: withDefaultOptions(Options{
			NSPrefetchThreshold: 2,
			NSAddrCacheEntries:  16,
		}),
		nsAddrCache: make(map[string]*nsAddrCacheEntry),
	}

	host := "ns1.example.net."
	r.storeNSHostIPs(host, []nsAddrCacheItem{{
		addr:      "198.51.100.10",
		expiresAt: time.Now().Add(3 * time.Second),
	}})

	ips, prefetch := r.getNSHostIPsFromCache(host)
	if len(ips) != 1 || ips[0] != "198.51.100.10" {
		t.Fatalf("unexpected cache ips: %#v", ips)
	}
	if prefetch {
		t.Fatalf("prefetch should not trigger on first hit")
	}

	ips, prefetch = r.getNSHostIPsFromCache(host)
	if len(ips) != 1 {
		t.Fatalf("expected cache hit")
	}
	if !prefetch {
		t.Fatalf("prefetch should trigger on second hit when ttl is near expiration")
	}
}

func TestStoreNSHostIPsEvictsExpired(t *testing.T) {
	r := &Resolver{
		opts: withDefaultOptions(Options{NSAddrCacheEntries: 1}),
		nsAddrCache: map[string]*nsAddrCacheEntry{
			"old.example.": {
				items: []nsAddrCacheItem{{addr: "192.0.2.10", expiresAt: time.Now().Add(-time.Second)}},
			},
		},
	}

	r.storeNSHostIPs("new.example.", []nsAddrCacheItem{{
		addr:      "198.51.100.5",
		expiresAt: time.Now().Add(30 * time.Second),
	}})

	if _, ok := r.nsAddrCache["new.example."]; !ok {
		t.Fatalf("expected new cache entry")
	}
	if _, ok := r.nsAddrCache["old.example."]; ok {
		t.Fatalf("expected expired entry to be evicted")
	}
}
