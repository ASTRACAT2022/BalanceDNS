package recursor

import (
	"testing"
	"time"
)

func TestWithDefaultOptionsPerformanceTunables(t *testing.T) {
	opts := withDefaultOptions(Options{WorkerCount: 4})
	if got, want := opts.NSLookupWorkers, 4; got != want {
		t.Fatalf("NSLookupWorkers=%d want=%d", got, want)
	}
	if got, want := opts.MaxNSAddressLookups, 24; got != want {
		t.Fatalf("MaxNSAddressLookups=%d want=%d", got, want)
	}
	if got, want := opts.MaxConcurrentExchanges, 4096; got != want {
		t.Fatalf("MaxConcurrentExchanges=%d want=%d", got, want)
	}
	if got, want := opts.NSAddrCacheEntries, 500000; got != want {
		t.Fatalf("NSAddrCacheEntries=%d want=%d", got, want)
	}
	if got, want := opts.NSPrefetchThreshold, 8; got != want {
		t.Fatalf("NSPrefetchThreshold=%d want=%d", got, want)
	}
	if got, want := opts.NSPrefetchConcurrency, 32; got != want {
		t.Fatalf("NSPrefetchConcurrency=%d want=%d", got, want)
	}
	if got, want := opts.HedgeDelay, 15*time.Millisecond; got != want {
		t.Fatalf("HedgeDelay=%s want=%s", got, want)
	}
	if got, want := opts.ZoneCutCacheEntries, 200000; got != want {
		t.Fatalf("ZoneCutCacheEntries=%d want=%d", got, want)
	}
}

func TestWithDefaultOptionsConcurrentExchangeFloor(t *testing.T) {
	opts := withDefaultOptions(Options{WorkerCount: 1})
	if got, want := opts.MaxConcurrentExchanges, 2048; got != want {
		t.Fatalf("MaxConcurrentExchanges=%d want=%d", got, want)
	}
	if got, want := opts.NSLookupWorkers, 2; got != want {
		t.Fatalf("NSLookupWorkers=%d want=%d", got, want)
	}
}
