package resolver

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolver_Resolve_Cache(t *testing.T) {
	cfg := config.NewConfig()
	m := metrics.NewMetrics()
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.LMDBPath, m)
	defer c.Close()
	res, err := NewResolver(ResolverType(cfg.ResolverType), cfg, c, m)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer res.Close()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)

	// First resolution should be a cache miss
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = res.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("First resolution failed: %v", err)
	}

	// Second resolution should be a cache hit
	startTime := time.Now()
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = res.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Second resolution failed: %v", err)
	}
	duration := time.Since(startTime)

	if duration > 10*time.Millisecond {
		t.Errorf("Expected cache hit to be faster, but it took %v", duration)
	}
}

func TestResolver_Resolve_SingleFlight(t *testing.T) {
	cfg := config.NewConfig()
	m := metrics.NewMetrics()
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.LMDBPath, m)
	defer c.Close()
	res, err := NewResolver(ResolverType(cfg.ResolverType), cfg, c, m)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer res.Close()

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)

	// Use a channel to synchronize the goroutines
	start := make(chan struct{})
	done := make(chan error, 2)

	// Start two goroutines to resolve the same domain concurrently
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := res.Resolve(ctx, req)
			done <- err
		}()
	}

	// Start the goroutines
	close(start)

	// Wait for the goroutines to finish
	for i := 0; i < 2; i++ {
		err := <-done
		if err != nil {
			t.Errorf("Concurrent resolution failed: %v", err)
		}
	}
}

func TestResolver_Resolve_DNSSEC(t *testing.T) {
	t.Skip("Skipping DNSSEC test because GoDNS resolver does not support it")
	cfg := config.NewConfig()
	m := metrics.NewMetrics()
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.LMDBPath, m)
	defer c.Close()
	res, err := NewResolver(ResolverType(cfg.ResolverType), cfg, c, m)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer res.Close()

	testCases := []struct {
		name        string
		domain      string
		qtype       uint16
		expectAD    bool
		expectErr   bool
		expectRcode int
	}{
		{
			name:     "Bogus Domain",
			domain:   "dnssec-failed.org.",
			qtype:    dns.TypeA,
			expectErr: true, // Expect an error because the signature is invalid
			expectRcode: dns.RcodeServerFailure,
		},
		{
			name:     "Secure Domain",
			domain:   "dnssec.works.",
			qtype:    dns.TypeA,
			expectAD: true,
		},
		{
			name:     "Insecure Domain",
			domain:   "example.com.",
			qtype:    dns.TypeA,
			expectAD: false,
		},
		{
			name:     "Vatican.va Domain",
			domain:   "vatican.va.",
			qtype:    dns.TypeA,
			expectAD: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.domain, tc.qtype)
			req.SetEdns0(4096, true) // Enable DNSSEC

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			resMsg, err := res.Resolve(ctx, req)
			if tc.expectErr {
				if err == nil {
					t.Errorf("Expected an error for domain %s, but got none", tc.domain)
				}
				if resMsg != nil && resMsg.Rcode != tc.expectRcode {
					t.Errorf("Expected Rcode %s for domain %s, but got %s",
						dns.RcodeToString[tc.expectRcode], tc.domain, dns.RcodeToString[resMsg.Rcode])
				}
			} else {
				if err != nil {
					if strings.Contains(err.Error(), "BOGUS") {
						t.Logf("Got expected BOGUS error: %v", err)
					} else {
						t.Errorf("Did not expect an error for domain %s, but got: %v", tc.domain, err)
					}
				}
				if resMsg == nil {
					t.Fatalf("Received nil response for domain %s", tc.domain)
				}
				if resMsg.Rcode != dns.RcodeSuccess && !tc.expectErr {
					t.Errorf("Expected Rcode NOERROR for domain %s, but got %s",
						tc.domain, dns.RcodeToString[resMsg.Rcode])
				}
				if tc.expectAD != resMsg.AuthenticatedData {
					t.Errorf("Expected AD bit to be %t, but got %t", tc.expectAD, resMsg.AuthenticatedData)
				}
			}
		})
	}
}
