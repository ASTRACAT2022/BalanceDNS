package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

// --- High-Performance TTL-Aware Cache ---

// cacheEntry holds the DNS message and its expiration time.
type cacheEntry struct {
	msg      *dns.Msg
	expiresAt time.Time
}

// TTLAwareCache provides a thread-safe, in-memory cache that respects DNS TTLs.
type TTLAwareCache struct {
	mu    sync.RWMutex
	items map[string]*cacheEntry
}

// NewTTLAwareCache creates a new instance of our TTL-aware cache.
func NewTTLAwareCache() *TTLAwareCache {
	return &TTLAwareCache{
		items: make(map[string]*cacheEntry),
	}
}

// cacheKey generates a consistent key for a given DNS query.
func (c *TTLAwareCache) cacheKey(zone string, question dns.Question) string {
	return fmt.Sprintf("%s:%s:%d:%d", zone, question.Name, question.Qtype, question.Qclass)
}

// Get retrieves a DNS message from the cache if it's still valid.
func (c *TTLAwareCache) Get(zone string, question dns.Question) (*dns.Msg, error) {
	c.mu.RLock()
	key := c.cacheKey(zone, question)
	entry, found := c.items[key]
	c.mu.RUnlock()

	if !found {
		return nil, nil // Cache miss
	}

	// Check if the entry has expired.
	if time.Now().After(entry.expiresAt) {
		// Entry is stale. Remove it from the cache.
		c.mu.Lock()
		delete(c.items, key)
		c.mu.Unlock()
		log.Printf("Cache expired for %s", question.Name)
		return nil, nil // Cache miss
	}

	log.Printf("Cache hit for %s", question.Name)
	return entry.msg.Copy(), nil
}

// Update stores a DNS message in the cache, calculating its TTL.
func (c *TTLAwareCache) Update(zone string, question dns.Question, msg *dns.Msg) error {
	// Find the minimum TTL in the response to use as the cache duration.
	minTTL := uint32(3600) // Default TTL of 1 hour for safety.
	if len(msg.Answer) > 0 {
		// Use the TTL from the first answer record as a baseline.
		minTTL = msg.Answer[0].Header().Ttl
		// Find the lowest TTL in the answer section.
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	} else {
		// For negative responses (e.g., NXDOMAIN), cache for a short time.
		minTTL = 300 // 5 minutes
	}

	// Never cache for more than a day or less than 10 seconds.
	if minTTL > 86400 {
		minTTL = 86400
	}
	if minTTL < 10 {
		minTTL = 10
	}

	duration := time.Duration(minTTL) * time.Second
	expiresAt := time.Now().Add(duration)

	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.cacheKey(zone, question)
	c.items[key] = &cacheEntry{
		msg:      msg.Copy(),
		expiresAt: expiresAt,
	}
	log.Printf("Cached %s, TTL: %s", question.Name, duration)
	return nil
}

// --- DNS Server Implementation ---

var recursiveResolver *resolver.Resolver

// dnsHandler processes incoming DNS queries.
func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		log.Println("Rejected query with no questions")
		return
	}

	question := r.Question[0]
	log.Printf("Received query for: %s, type: %s", question.Name, dns.TypeToString[question.Qtype])

	recursiveQuery := new(dns.Msg)
	recursiveQuery.SetQuestion(question.Name, question.Qtype)
	recursiveQuery.SetEdns0(4096, true)

	result := recursiveResolver.Exchange(context.Background(), recursiveQuery)

	if result.Err != nil {
		log.Printf("Recursive resolution failed for %s: %v", question.Name, result.Err)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	log.Printf("Successfully resolved %s", question.Name)
	m.Answer = result.Msg.Answer
	m.Ns = result.Msg.Ns
	m.Extra = result.Msg.Extra
	m.Rcode = result.Msg.Rcode

	w.WriteMsg(m)
}

func main() {
	// --- Initialize the Recursive Resolver with our new TTL-aware cache ---
	resolver.Cache = NewTTLAwareCache()
	resolver.Query = func(s string) { /* Suppress verbose recursive logs for server clarity */ }
	recursiveResolver = resolver.NewResolver()

	dns.HandleFunc(".", dnsHandler)

	port := 5053
	// Listen on both UDP and TCP
	go func() {
		server := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: "udp"}
		log.Printf("Starting DNS server on port %d (UDP)", port)
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start UDP server: %s\n", err.Error())
		}
	}()
	go func() {
		server := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: "tcp"}
		log.Printf("Starting DNS server on port %d (TCP)", port)
		err := server.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to start TCP server: %s\n", err.Error())
		}
	}()

	// Keep the main goroutine alive.
	select {}
}