package resolver

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolver_Resolve(t *testing.T) {
	// Create a new cache and resolver for the test.
	cfg := config.NewConfig()
	dir, err := os.MkdirTemp("", "test-resolver-lmdb")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	m := metrics.NewMetrics()
	c := cache.NewCache(cache.DefaultCacheSize, cache.DefaultShards, dir, m)
	defer c.Close()
	r, err := NewResolver(ResolverTypeUnbound, cfg, c, m)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}

	// Define the question to test.
	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	req.RecursionDesired = true
	req.SetEdns0(4096, true) // Enable DNSSEC OK bit

	// Resolve the domain.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := r.Resolve(ctx, req)

	// Check for errors.
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	// Check if we got a response.
	if msg == nil {
		t.Fatal("Resolve() returned a nil message.")
	}

	// Check if the response contains at least one answer.
	if len(msg.Answer) == 0 {
		t.Fatal("Response contains no answer records.")
	}

	// Check if the response code is NOERROR.
	if msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("Response code is not NOERROR, got %s", dns.RcodeToString[msg.Rcode])
	}

	t.Logf("Successfully resolved %s", req.Question[0].Name)
	for _, ans := range msg.Answer {
		t.Logf(" -> %s", ans.String())
	}
}

func TestResolver_Resolve_DNSSEC(t *testing.T) {
	cfg := config.NewConfig()
	// Use a longer timeout for DNSSEC queries as they can be slower.
	cfg.RequestTimeout = 20 * time.Second
	dir, err := os.MkdirTemp("", "test-resolver-dnssec-lmdb")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	m := metrics.NewMetrics()
	c := cache.NewCache(cache.DefaultCacheSize, cache.DefaultShards, dir, m)
	defer c.Close()
	r, err := NewResolver(ResolverTypeUnbound, cfg, c, m)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}

	testCases := []struct {
		name          string
		domain        string
		qtype         uint16
		expectADBit   bool
		expectRCode   int
		expectError   bool
		expectAnswers bool
	}{
		{
			name:          "Secure Domain",
			domain:        "dnssec.works.",
			qtype:         dns.TypeA,
			expectADBit:   true,
			expectRCode:   dns.RcodeSuccess,
			expectError:   false,
			expectAnswers: true,
		},
		{
			name:          "Insecure Domain",
			domain:        "vatican.va.",
			qtype:         dns.TypeA,
			expectADBit:   false,
			expectRCode:   dns.RcodeSuccess,
			expectError:   false,
			expectAnswers: true,
		},
		{
			name:        "Bogus Domain",
			domain:      "dnssec-failed.org.",
			qtype:       dns.TypeA,
			expectADBit: false,
			// The resolver should return an error for bogus domains.
			// The underlying library returns an error, which we propagate.
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.domain, tc.qtype)
			req.SetEdns0(4096, true)

			ctx, cancel := context.WithTimeout(context.Background(), cfg.RequestTimeout)
			defer cancel()

			msg, err := r.Resolve(ctx, req)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected an error for domain %s, but got none", tc.domain)
				}
				// If we expect an error, we don't need to check the message.
				return
			}

			if err != nil {
				t.Fatalf("Resolve() failed for %s: %v", tc.domain, err)
			}

			if msg == nil {
				t.Fatalf("Resolve() returned a nil message for %s.", tc.domain)
			}

			if msg.Rcode != tc.expectRCode {
				t.Errorf("Expected RCode %s, but got %s", dns.RcodeToString[tc.expectRCode], dns.RcodeToString[msg.Rcode])
			}

			if msg.AuthenticatedData != tc.expectADBit {
				t.Errorf("Expected AD bit to be %t, but got %t", tc.expectADBit, msg.AuthenticatedData)
			}

			if tc.expectAnswers && len(msg.Answer) == 0 {
				t.Errorf("Expected answers for %s, but got none", tc.domain)
			}
		})
	}
}
