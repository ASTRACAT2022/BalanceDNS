package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Helper function to start the server in the background for integration tests
func runServerForPerfTest(ctx context.Context, cancel context.CancelFunc) {
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

type PerfTestClient struct {
	client *dns.Client
}

func NewPerfTestClient() *PerfTestClient {
	return &PerfTestClient{
		client: &dns.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *PerfTestClient) Query(domain string, qtype uint16) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	// Send to the local resolver
	r, _, err := c.client.Exchange(m, "127.0.0.1:5053")
	if err != nil {
		return err
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS error: %s", dns.RcodeToString[r.Rcode])
	}
	return nil
}

func TestPerformance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runServerForPerfTest(ctx, cancel)
	time.Sleep(2 * time.Second) // Wait for server to be ready

	client := NewPerfTestClient()

	// Test domains
	domains := []string{
		"google.com",
		"github.com",
		"stackoverflow.com",
		"amazon.com",
		"microsoft.com",
	}

	fmt.Println("Starting DNS resolver performance test...")

	// Warm-up phase
	fmt.Println("Warm-up phase (10 queries)...")
	for i := 0; i < 10; i++ {
		_ = client.Query(domains[i%len(domains)], dns.TypeA)
	}

	// Performance test with concurrency
	fmt.Println("Performance test starting...")

	// Test 1: Concurrent queries
	const numWorkers = 50
	const queriesPerWorker = 100
	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < queriesPerWorker; j++ {
				domain := domains[(workerID+j)%len(domains)]
				err := client.Query(domain, dns.TypeA)
				if err != nil {
					log.Printf("Worker %d: Query %s failed: %v", workerID, domain, err)
				}
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalQueries := numWorkers * queriesPerWorker
	qps := float64(totalQueries) / elapsed.Seconds()

	fmt.Printf("\nPerformance Results:\n")
	fmt.Printf("Total queries: %d\n", totalQueries)
	fmt.Printf("Time elapsed: %v\n", elapsed)
	fmt.Printf("QPS: %.2f\n", qps)
	fmt.Printf("Goroutines: %d\n", runtime.NumGoroutine())

	// Test 2: Latency test
	fmt.Println("\nLatency test...")
	latencyStart := time.Now()
	for i := 0; i < 100; i++ {
		_ = client.Query("google.com", dns.TypeA)
	}
	latencyAvg := time.Since(latencyStart) / 100
	fmt.Printf("Average latency: %v\n", latencyAvg)

	// Test 3: Cache efficiency test
	fmt.Println("\nCache efficiency test...")
	cacheStart := time.Now()
	// Same query repeated to test cache
	for i := 0; i < 1000; i++ {
		_ = client.Query("google.com", dns.TypeA)
	}
	cacheAvg := time.Since(cacheStart) / 1000
	fmt.Printf("Average cached query latency: %v\n", cacheAvg)

	fmt.Println("\nPerformance test completed!")
}
