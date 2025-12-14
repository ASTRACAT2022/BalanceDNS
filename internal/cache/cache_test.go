package cache

import (
	"dns-resolver/internal/metrics"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Helper function to create a temporary directory and a new cache instance for testing.
func newTestCache(t *testing.T) (*Cache, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "test-lmdb")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	m := metrics.NewMetrics("")
	cache := NewCache(128, 1, dir, m)

	cleanup := func() {
		cache.Close()
		os.RemoveAll(dir)
	}

	return cache, cleanup
}

// Helper function to create a simple DNS message for testing.
func createTestMsg(qname string, ttl uint32, answer string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	if answer != "" {
		rr, _ := dns.NewRR(dns.Fqdn(qname) + " " + strconv.Itoa(int(ttl)) + " IN A " + answer)
		msg.Answer = []dns.RR{rr}
	}
	return msg
}

func TestCacheSetAndGet(t *testing.T) {
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	msg := createTestMsg("example.com.", 60, "1.2.3.4")

	c.Set(key, msg, 0)

	retrievedBytes, found, revalidate := c.Get(key)
	if !found {
		t.Fatal("expected to find message in cache, but didn't")
	}
	if revalidate {
		t.Error("expected revalidate to be false for a fresh entry")
	}
	retrievedMsg := new(dns.Msg)
	if err := retrievedMsg.Unpack(retrievedBytes); err != nil {
		t.Fatalf("Failed to unpack retrieved message: %v", err)
	}
}

func TestCacheNotFound(t *testing.T) {
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "notfound.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)

	_, found, _ := c.Get(key)
	if found {
		t.Fatal("expected to not find message in cache, but did")
	}
}

func TestCacheExpiration(t *testing.T) {
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "shortlived.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	msg := createTestMsg("shortlived.com.", 1, "2.3.4.5")

	c.Set(key, msg, 0)

	time.Sleep(1100 * time.Millisecond)

	_, found, _ := c.Get(key)
	if found {
		t.Fatal("expected message to be expired and not found, but it was found")
	}
}

func TestCachePersistence(t *testing.T) {
	dir, err := os.MkdirTemp("", "test-lmdb-persistence")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	q := dns.Question{Name: "persistent.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	msg := createTestMsg("persistent.com.", 60, "5.6.7.8")

	m := metrics.NewMetrics("")
	// Create the first cache, add an item, and close it to persist the data.
	c1 := NewCache(128, 1, dir, m)
	c1.Set(key, msg, 0)
	c1.Close()

	// Create a new cache from the same DB path to load the data.
	c2 := NewCache(128, 1, dir, m)
	defer c2.Close()

	// Verify the item is present in the new cache.
	retrievedBytes, found, _ := c2.Get(key)
	if !found {
		t.Fatal("expected to find message in persisted cache, but didn't")
	}
	retrievedMsg := new(dns.Msg)
	if err := retrievedMsg.Unpack(retrievedBytes); err != nil {
		t.Fatalf("Failed to unpack retrieved message: %v", err)
	}
	if len(retrievedMsg.Answer) != 1 || retrievedMsg.Answer[0].Header().Name != "persistent.com." {
		t.Errorf("unexpected answer in retrieved message: %v", retrievedMsg.Answer)
	}
}

func TestCachePersistenceExpiration(t *testing.T) {
	dir, err := os.MkdirTemp("", "test-lmdb-persistence-expired")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	q := dns.Question{Name: "expired-persistent.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	msg := createTestMsg("expired-persistent.com.", 1, "9.8.7.6") // 1-second TTL

	m := metrics.NewMetrics("")
	// Create the first cache, add an item, and close it.
	c1 := NewCache(128, 1, dir, m)
	c1.Set(key, msg, 0)
	c1.Close()

	// Wait for the item to expire.
	time.Sleep(1100 * time.Millisecond)

	// Create a new cache from the same DB path.
	c2 := NewCache(128, 1, dir, m)
	defer c2.Close()

	// The expired item should not be loaded.
	_, found, _ := c2.Get(key)
	if found {
		t.Fatal("found an expired message in the cache, but it should have been ignored on load")
	}
}

func TestCacheStaleWhileRevalidate(t *testing.T) {
	c, cleanup := newTestCache(t)
	defer cleanup()

	q := dns.Question{Name: "stale.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	key := Key(q)
	// TTL of 1 second, SWR of 5 seconds
	msg := createTestMsg("stale.com.", 1, "3.4.5.6")
	swrDuration := 5 * time.Second

	c.Set(key, msg, swrDuration)

	// Wait for item to become stale but not fully expired from SWR window
	time.Sleep(1100 * time.Millisecond)

	retrievedBytes, found, revalidate := c.Get(key)
	if !found {
		t.Fatal("expected to get stale message, but got nothing")
	}
	if !revalidate {
		t.Error("expected revalidate to be true for a stale entry")
	}
	retrievedMsg := new(dns.Msg)
	if err := retrievedMsg.Unpack(retrievedBytes); err != nil {
		t.Fatalf("Failed to unpack retrieved message: %v", err)
	}
	if len(retrievedMsg.Answer) != 1 {
		t.Fatalf("expected 1 answer in stale message, got %d", len(retrievedMsg.Answer))
	}

	// Wait for the SWR window to close
	time.Sleep(swrDuration)

	// After the SWR window, the item should be gone
	_, found, _ = c.Get(key)
	if found {
		t.Fatal("expected message to be expired and not found after SWR window, but it was found")
	}
}

func BenchmarkCacheSet(b *testing.B) {
	m := metrics.NewMetrics("")
	dir, err := os.MkdirTemp("", "bench-lmdb-set")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	c := NewCache(100000, 256, dir, m)
	defer c.Close()

	msg := createTestMsg("example.com.", 3600, "1.2.3.4")
	key := Key(msg.Question[0])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(key, msg, 0)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	m := metrics.NewMetrics("")
	dir, err := os.MkdirTemp("", "bench-lmdb-get")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	c := NewCache(100000, 256, dir, m)
	defer c.Close()

	msg := createTestMsg("example.com.", 3600, "1.2.3.4")
	key := Key(msg.Question[0])
	c.Set(key, msg, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Get(key)
	}
}

func BenchmarkFastCacheSetAndGet(b *testing.B) {
	c := NewFastCache(100000, 256)
	msg := createTestMsg("example.com.", 3600, "1.2.3.4")
	key := Key(msg.Question[0])
	packedMsg, _ := msg.Pack()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(key, packedMsg, 3600*time.Second, 0)
		c.Get(key)
	}
}