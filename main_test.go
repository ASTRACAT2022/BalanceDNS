package main

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestMain runs the main function in a separate goroutine and then runs tests.
// This is a simple way to write an integration test for the server.
func TestMain(m *testing.M) {
	// Start the server in the background
	go func() {
		// Suppress log output from the server during tests
		log.SetOutput(os.NewFile(0, os.DevNull))
		main()
	}()

	// Give the server a moment to start up
	time.Sleep(1 * time.Second)

	// Run the tests
	exitCode := m.Run()

	// Exit with the test result
	os.Exit(exitCode)
}

func TestIntegration_ResolveA(t *testing.T) {
	client := new(dns.Client)
	msg := new(dns.Msg)
	// Using cloudflare.com as it's a well-known, stable domain.
	msg.SetQuestion("cloudflare.com.", dns.TypeA)

	// The server is running on the default address from config.
	serverAddr := "127.0.0.1:5053"

	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		t.Fatalf("Failed to exchange with server: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[resp.Rcode])
	}

	if len(resp.Answer) == 0 {
		t.Error("Expected to receive at least one answer")
	}
}

func TestIntegration_ResolveDNSSEC(t *testing.T) {
	client := new(dns.Client)
	msg := new(dns.Msg)
	// Using ripe.net as it's known to be DNSSEC-signed.
	msg.SetQuestion("ripe.net.", dns.TypeA)
	// Set the DO (DNSSEC OK) bit to request DNSSEC data.
	msg.SetEdns0(4096, true)

	serverAddr := "127.0.0.1:5053"

	resp, _, err := client.Exchange(msg, serverAddr)
	if err != nil {
		t.Fatalf("Failed to exchange with server: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %s", dns.RcodeToString[resp.Rcode])
	}

	if len(resp.Answer) == 0 {
		t.Error("Expected to receive at least one answer")
	}

	// Check for the AD (Authenticated Data) bit in the response.
	// This indicates that the resolver was able to validate the data.
	if !resp.AuthenticatedData {
		t.Error("Expected Authenticated Data (AD) bit to be set for a DNSSEC-signed domain")
	}
}

func BenchmarkResolve(b *testing.B) {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	serverAddr := "127.0.0.1:5053"

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := client.Exchange(msg, serverAddr)
			if err != nil {
				b.Error(err)
			}
		}
	})
}
