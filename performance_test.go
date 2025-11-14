package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
)

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

func main() {
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