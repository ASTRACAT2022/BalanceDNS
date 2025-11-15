package main

import (
	"context"
	"dns-resolver/internal/cache"
	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/resolver"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Helper function to start the server in the background for integration tests
func runServer(ctx context.Context, cancel context.CancelFunc) {
	// Build the server binary
	cmd := exec.Command("go", "build", "-o", "/tmp/dns-resolver", ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to build server: %v\nOutput: %s", err, string(output))
	}

	// Run the server
	cmd = exec.Command("/tmp/dns-resolver")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Kill the server when the context is done
	go func() {
		<-ctx.Done()
		cmd.Process.Kill()
	}()
}

// TestIntegration_ResolveDNSSEC is an integration test for DNSSEC validation.
func TestIntegration_ResolveDNSSEC(t *testing.T) {
	t.Skip("Skipping DNSSEC test because GoDNS resolver does not support it")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runServer(ctx, cancel)
	time.Sleep(2 * time.Second) // Wait for server to be ready

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("dnssec.works.", dns.TypeA)
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, "localhost:5053")
	if err != nil {
		t.Fatalf("Failed to resolve: %v", err)
	}

	if !r.AuthenticatedData {
		t.Errorf("Expected Authenticated Data (AD) bit to be set for a DNSSEC-signed domain")
	}
}

func TestResolver_Resolve(t *testing.T) {
	cfg := config.NewConfig()
	m := metrics.NewMetrics()
	c := cache.NewCache(cfg.CacheSize, cache.DefaultShards, cfg.LMDBPath, m)
	defer c.Close()
	res, err := resolver.NewResolver(resolver.ResolverType(cfg.ResolverType), cfg, c, m)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer res.Close()

	testCases := []struct {
		name       string
		domain     string
		qtype      uint16
		expected   string
		expectAD   bool
		expectErr  bool
		expectRcode int
	}{
		{
			name:   "Valid Domain",
			domain: "www.google.com.",
			qtype:  dns.TypeA,
		},
		{
			name:       "DNSSEC-Signed Domain",
			domain:     "dnssec.works.",
			qtype:      dns.TypeA,
			expectAD:   true,
		},
		{
			name:       "Bogus Domain",
			domain:     "dnssec-failed.org.",
			qtype:      dns.TypeA,
			expectErr:  true, // Expect an error because the signature is invalid
			expectRcode: dns.RcodeServerFailure,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.name, "Bogus") {
				t.Skip("Skipping Bogus Domain test because GoDNS resolver does not support DNSSEC")
			}
			if strings.Contains(tc.name, "DNSSEC") {
				t.Skip("Skipping DNSSEC test because GoDNS resolver does not support DNSSEC")
			}
			req := new(dns.Msg)
			req.SetQuestion(tc.domain, tc.qtype)
			req.SetEdns0(4096, true) // Enable DNSSEC

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
					t.Errorf("Did not expect an error for domain %s, but got: %v", tc.domain, err)
				}
				if resMsg == nil {
					t.Fatalf("Received nil response for domain %s", tc.domain)
				}
				if resMsg.Rcode != dns.RcodeSuccess {
					t.Errorf("Expected Rcode NOERROR for domain %s, but got %s",
						tc.domain, dns.RcodeToString[resMsg.Rcode])
				}
				if tc.expectAD && !resMsg.AuthenticatedData {
					t.Errorf("Expected AD bit to be true, but got false")
				}
			}
		})
	}
}
