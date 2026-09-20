// loadgen sends DNS queries to a target at a given QPS and reports latency
// percentiles and throughput. Uses a fixed worker pool for efficiency.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1:15353", "target DNS server")
	qps := flag.Int("qps", 1000, "target queries per second")
	duration := flag.Int("duration", 5, "test duration in seconds")
	domains := flag.Int("domains", 100, "number of distinct domains to cycle")
	workers := flag.Int("workers", 50, "number of worker goroutines")
	flag.Parse()

	names := make([]string, *domains)
	for i := range names {
		names[i] = fmt.Sprintf("load%d.example.", i)
	}

	var sent, okCount, errCount int64
	var mu sync.Mutex
	var latencies []time.Duration

	interval := time.Duration(float64(time.Second) / float64(*qps))
	deadline := time.Now().Add(time.Duration(*duration) * time.Second)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Rate limiter: token bucket via ticker shared by workers.
	limiter := time.NewTicker(interval)
	defer limiter.Stop()

	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
			for {
				select {
				case <-stop:
					return
				case <-limiter.C:
				}
				if time.Now().After(deadline) {
					return
				}
				name := names[rand.Intn(len(names))]
				req := new(dns.Msg)
				req.SetQuestion(name, dns.TypeA)
				atomic.AddInt64(&sent, 1)
				start := time.Now()
				resp, _, err := client.Exchange(req, *server)
				lat := time.Since(start)
				mu.Lock()
				latencies = append(latencies, lat)
				mu.Unlock()
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				if resp != nil && resp.Rcode == dns.RcodeSuccess {
					atomic.AddInt64(&okCount, 1)
				}
			}
		}()
	}

	// Wait for deadline, then stop workers.
	time.Sleep(time.Until(deadline))
	close(stop)
	wg.Wait()

	mu.Lock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	total := len(latencies)
	p := func(q float64) time.Duration {
		if total == 0 {
			return 0
		}
		idx := int(float64(total) * q)
		if idx >= total {
			idx = total - 1
		}
		return latencies[idx]
	}
	elapsed := time.Duration(*duration) * time.Second
	fmt.Printf("target_qps=%d sent=%d ok=%d err=%d\n", *qps, sent, okCount, errCount)
	fmt.Printf("actual_qps=%.0f\n", float64(sent)/elapsed.Seconds())
	fmt.Printf("p50=%s p95=%s p99=%s max=%s\n", p(0.50), p(0.95), p(0.99), p(1.0))
	mu.Unlock()
}
