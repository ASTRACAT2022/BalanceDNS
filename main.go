package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

const (
	port                      = ":5053"
	defaultShards             = 32              // Example: 32 shards
	maxCacheEntriesPerShard   = 1000            // Max entries per cache shard
	cacheCleanupInterval      = 5 * time.Minute // Interval for cleaning up expired cache entries
)

type DnsJob struct {
	w  dns.ResponseWriter
	req *dns.Msg
	shardedCache *ShardedCache
	r *resolver.Resolver
}

func (j *DnsJob) Execute() {
	// Generate a more robust cache key from the DNS question (Name, Type, Class)
	q := j.req.Question[0]
	cacheKey := fmt.Sprintf("%s:%s:%s", q.Name, dns.TypeToString[q.Qtype], dns.ClassToString[q.Qclass])

	// Try to get the response from cache
	if cachedMsg, found, _ := j.shardedCache.Get(cacheKey); found {
		log.Printf("Cache HIT for %s", cacheKey)
		// The cached message has the correct RCODE, just set the ID and send it.
		cachedMsg.Id = j.req.Id
		j.w.WriteMsg(cachedMsg)
		return
	}

	log.Printf("Cache MISS for %s", cacheKey)
	// Create a new message to pass to the resolver. It's good practice to create a new one
	// rather than modifying the client's request.
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.SetEdns0(4096, true) // Enable EDNS0 with DNSSEC OK bit

	result := j.r.Exchange(context.Background(), msg)
	if result.Err != nil {
		log.Printf("Error exchanging DNS query for %s: %v", cacheKey, result.Err)
		m := new(dns.Msg)
		m.SetRcode(j.req, dns.RcodeServerFailure)
		j.w.WriteMsg(m)
		// Cache the SERVFAIL response for a short period to prevent hammering on errors.
		j.shardedCache.Set(cacheKey, m, 30*time.Second, false) // Not DNSSEC validated
		return
	}

	// The query was successful (no transport error), now process the response.
	responseMsg := result.Msg
	responseMsg.Id = j.req.Id
	responseMsg.RecursionAvailable = true // We are a recursive resolver

	// Determine TTL for caching.
	// Use a small default TTL, but prefer the TTL from the SOA record for negative responses.
	ttl := 60 * time.Second // Default TTL for positive responses
	if responseMsg.Rcode != dns.RcodeSuccess {
		// For negative responses (NXDOMAIN, etc.), find the SOA record for the TTL.
		for _, ns := range responseMsg.Ns {
			if soa, ok := ns.(*dns.SOA); ok {
				// The negative TTL is the minimum of the SOA's TTL and the SOA's Minimum field.
				ttl = time.Duration(min(soa.Header().Ttl, soa.Minttl)) * time.Second
				break
			}
		}
	} else if len(responseMsg.Answer) > 0 {
		// For positive responses, use the minimum TTL from the answer section.
		minTTL := responseMsg.Answer[0].Header().Ttl
		for _, rr := range responseMsg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		ttl = time.Duration(minTTL) * time.Second
	}

	dnssecValidated := responseMsg.AuthenticatedData

	// If DNSSEC is not validated, it's good practice to use a shorter TTL
	// to encourage re-validation sooner.
	if !dnssecValidated {
		// Let's be more conservative than 5s. 60s is a reasonable minimum.
		if ttl > 60*time.Second {
			ttl = 60 * time.Second
		}
	}

	// Cache the response (positive or negative, like NXDOMAIN)
	j.shardedCache.Set(cacheKey, responseMsg, ttl, dnssecValidated)

	j.w.WriteMsg(responseMsg)
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func main() {
	// Override the default logging hook on resolver.
	resolver.Query = func(s string) {
		fmt.Println("Query: " + s)
	}

	// Initialize Sharded Cache
	shardedCache := NewShardedCache(defaultShards, maxCacheEntriesPerShard, cacheCleanupInterval)
	defer shardedCache.Stop()

	// Initialize Worker Pool
	workerPool := NewWorkerPool(100, 1000) // 100 workers, 1000 job queue size
	workerPool.Start()
	defer workerPool.Stop()

	r := resolver.NewResolver()

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		job := &DnsJob{
			w:  w,
			req: req,
			shardedCache: shardedCache,
			r: r,
		}
		workerPool.Submit(job)
	})

	server := &dns.Server{
		Addr:    port,
		Net:     "udp",
		UDPSize: 65535, // Set UDPSize to max for EDNS0
	}

	log.Printf("Starting DNS resolver on %s", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}