package goresolver

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSCache_AddAndGet(t *testing.T) {
	cache := NewDNSCache(10, 10)
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	// Test adding and getting a valid entry
	cache.Add("example.com:A", msg, time.Minute, false)
	if cachedMsg, _, found, _ := cache.Get("example.com:A"); !found || cachedMsg == nil {
		t.Error("Failed to retrieve cached message")
	}

	// Test TTL expiration
	cache.Add("expired.com:A", msg, time.Microsecond, false)
	time.Sleep(time.Millisecond)
	if _, _, found, _ := cache.Get("expired.com:A"); found {
		t.Error("Expired entry should not be found")
	}
}

func TestDNSCache_NegativeCache(t *testing.T) {
	cache := NewDNSCache(10, 10)
	msg := &dns.Msg{}
	msg.SetQuestion("nonexistent.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError

	// Test negative caching
	cache.Add("nonexistent.com:A", msg, time.Minute, true)
	if _, _, found, isNegative := cache.Get("nonexistent.com:A"); !found || !isNegative {
		t.Error("Failed to retrieve negative cache entry")
	}
}

func TestDNSCache_Sharding(t *testing.T) {
	cache := NewDNSCache(2, 10) // 2 shards
	msg := &dns.Msg{}
	msg.SetQuestion("shard1.com.", dns.TypeA)

	// Test shard distribution
	cache.Add("shard1.com:A", msg, time.Minute, false)
	cache.Add("shard2.com:A", msg, time.Minute, false)
	cache.Add("shard3.com:A", msg, time.Minute, false)

	// Verify entries are distributed across shards
	if _, _, found, _ := cache.Get("shard1.com:A"); !found {
		t.Error("Entry in shard1 not found")
	}
	if _, _, found, _ := cache.Get("shard2.com:A"); !found {
		t.Error("Entry in shard2 not found")
	}
	if _, _, found, _ := cache.Get("shard3.com:A"); !found {
		t.Error("Entry in shard3 not found")
	}
}

func TestDNSCache_LRUEviction(t *testing.T) {
	cache := NewDNSCache(1, 2) // 1 shard, max size 2
	msg1 := &dns.Msg{}
	msg1.SetQuestion("first.com.", dns.TypeA)
	msg2 := &dns.Msg{}
	msg2.SetQuestion("second.com.", dns.TypeA)
	msg3 := &dns.Msg{}
	msg3.SetQuestion("third.com.", dns.TypeA)

	// Add 3 entries to a cache of size 2
	cache.Add("first.com:A", msg1, time.Minute, false)
	cache.Add("second.com:A", msg2, time.Minute, false)
	cache.Add("third.com:A", msg3, time.Minute, false)

	// "first.com:A" should be evicted
	if _, _, found, _ := cache.Get("first.com:A"); found {
		t.Error("Least recently used entry was not evicted")
	}

	// "second.com:A" and "third.com:A" should be present
	if _, _, found, _ := cache.Get("second.com:A"); !found {
		t.Error("Second entry should not be evicted")
	}
	if _, _, found, _ := cache.Get("third.com:A"); !found {
		t.Error("Third entry should not be evicted")
	}

	// Accessing second.com should make it the most recently used
	cache.Get("second.com:A")

	// Add a fourth entry, which should evict third.com
	msg4 := &dns.Msg{}
	msg4.SetQuestion("fourth.com.", dns.TypeA)
	cache.Add("fourth.com:A", msg4, time.Minute, false)

	if _, _, found, _ := cache.Get("third.com:A"); found {
		t.Error("Entry that was not most recently used was not evicted")
	}
}

func TestDNSCache_ConcurrentAccess(t *testing.T) {
	cache := NewDNSCache(4, 100)
	var wg sync.WaitGroup
	numGoroutines := 50
	numOps := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				key := fmt.Sprintf("domain-%d-%d.com:A", i, j)
				msg := &dns.Msg{}
				msg.SetQuestion(key, dns.TypeA)

				// Add and then immediately get
				cache.Add(key, msg, time.Minute, false)
				cache.Get(key)
			}
		}(i)
	}

	wg.Wait()
	// The test passes if it completes without panicking, especially when run with the -race flag.
}