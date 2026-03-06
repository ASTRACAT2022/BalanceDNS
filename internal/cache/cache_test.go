package cache

import (
	"path/filepath"
	"testing"
	"time"
)

func waitFor(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

func TestCacheSetGetAndExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cache.db")

	c, err := NewCache(8, dbPath)
	if err != nil {
		t.Fatalf("NewCache failed: %v", err)
	}
	defer c.Close()

	key := "1:example.com."
	decision := &Decision{Action: ActionPass}
	c.Set(key, decision, 1*time.Second)
	c.l1.Wait()

	if _, ok := c.Get(key); !ok {
		t.Fatal("expected cache hit right after set")
	}

	// Force L2 path by clearing L1 and giving writer some time to flush.
	c.l1.Clear()
	if ok := waitFor(500*time.Millisecond, func() bool {
		_, ok := c.Get(key)
		return ok
	}); !ok {
		t.Fatal("expected L2 cache hit after L1 clear")
	}

	// Ensure expired items are not served.
	time.Sleep(1200 * time.Millisecond)
	c.l1.Clear()
	if _, ok := c.Get(key); ok {
		t.Fatal("expected cache miss after ttl expiration")
	}
}

func TestCacheSetWithNonPositiveTTLIsIgnored(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "cache.db")

	c, err := NewCache(8, dbPath)
	if err != nil {
		t.Fatalf("NewCache failed: %v", err)
	}
	defer c.Close()

	key := "1:ignored.example."
	decision := &Decision{Action: ActionPass}
	c.Set(key, decision, 0)
	c.l1.Wait()
	c.l1.Clear()

	if _, ok := c.Get(key); ok {
		t.Fatal("expected miss for zero ttl set")
	}
}
