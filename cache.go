package goresolver

import (
	"container/list"
	"runtime"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry represents a cached DNS response with its expiration time.
type CacheEntry struct {
	Key        string
	Message    *dns.Msg
	Timestamp  time.Time
	TTL        time.Duration
	IsNegative bool
}

// DNSCache implements a time-aware, sharded, LRU cache for DNS responses.
type DNSCache struct {
	shards    []*cacheShard
	numShards uint32
	stopCh    chan struct{}
}

type cacheShard struct {
	entries map[string]*list.Element
	lruList *list.List
	maxSize int
	mu      sync.Mutex // Using a full mutex as we are modifying the list order on Get
}

// NewDNSCache creates a new DNSCache with the specified number of shards and max size per shard.
func NewDNSCache(numShards int, maxSizePerShard int) *DNSCache {
	if numShards <= 0 {
		numShards = 1 // Ensure at least one shard
	}
	if maxSizePerShard <= 0 {
		maxSizePerShard = 1024 // Default max size
	}
	shards := make([]*cacheShard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &cacheShard{
			entries: make(map[string]*list.Element),
			lruList: list.New(),
			maxSize: maxSizePerShard,
		}
	}
	cache := &DNSCache{
		shards:    shards,
		numShards: uint32(numShards),
		stopCh:    make(chan struct{}),
	}

	go cache.startCleanup(5 * time.Minute)
	runtime.SetFinalizer(cache, (*DNSCache).StopCleanup)

	return cache
}

// startCleanup runs a background goroutine to periodically remove expired entries.
func (c *DNSCache) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanupExpired()
		case <-c.stopCh:
			return
		}
	}
}

// StopCleanup stops the background cleanup goroutine.
func (c *DNSCache) StopCleanup() {
	if c.stopCh != nil {
		close(c.stopCh)
		c.stopCh = nil
	}
}

// cleanupExpired iterates over all shards and removes expired entries.
func (c *DNSCache) cleanupExpired() {
	for _, shard := range c.shards {
		shard.mu.Lock()
		// Iterate from the back of the list (least recently used)
		for elem := shard.lruList.Back(); elem != nil; {
			prev := elem.Prev()
			entry := elem.Value.(*CacheEntry)
			if time.Since(entry.Timestamp) >= entry.TTL {
				// Expired, remove it
				shard.lruList.Remove(elem)
				delete(shard.entries, entry.Key)
			} else {
				// Items are ordered by recent use. If this one isn't expired, the ones before it won't be either.
				break
			}
			elem = prev
		}
		shard.mu.Unlock()
	}
}

// getShard returns the appropriate shard for a given key.
func (c *DNSCache) getShard(key string) *cacheShard {
	h := fnv32(key)
	return c.shards[h%c.numShards]
}

// Add adds a DNS message to the cache with a given TTL.
func (c *DNSCache) Add(key string, msg *dns.Msg, ttl time.Duration, isNegative bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if elem, ok := shard.entries[key]; ok {
		// Entry exists, update it and move to front
		shard.lruList.MoveToFront(elem)
		entry := elem.Value.(*CacheEntry)
		entry.Message = msg
		entry.Timestamp = time.Now()
		entry.TTL = ttl
		entry.IsNegative = isNegative
		return
	}

	// Evict if cache is full
	if shard.lruList.Len() >= shard.maxSize {
		elem := shard.lruList.Back()
		if elem != nil {
			entryToEvict := shard.lruList.Remove(elem).(*CacheEntry)
			delete(shard.entries, entryToEvict.Key)
		}
	}

	// Add new entry
	entry := &CacheEntry{
		Key:        key,
		Message:    msg,
		Timestamp:  time.Now(),
		TTL:        ttl,
		IsNegative: isNegative,
	}
	elem := shard.lruList.PushFront(entry)
	shard.entries[key] = elem
}

// Get retrieves a DNS message from the cache.
func (c *DNSCache) Get(key string) (*dns.Msg, time.Duration, bool, bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if elem, found := shard.entries[key]; found {
		entry := elem.Value.(*CacheEntry)

		if time.Since(entry.Timestamp) >= entry.TTL {
			// Expired, remove it
			shard.lruList.Remove(elem)
			delete(shard.entries, key)
			return nil, 0, false, false
		}

		// Not expired, move to front
		shard.lruList.MoveToFront(elem)
		return entry.Message, entry.TTL - time.Since(entry.Timestamp), true, entry.IsNegative
	}

	return nil, 0, false, false
}

// Delete removes a DNS message from the cache.
func (c *DNSCache) Delete(key string) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if elem, found := shard.entries[key]; found {
		shard.lruList.Remove(elem)
		delete(shard.entries, key)
	}
}

// fnv32 generates a 32-bit FNV hash for a string.
func fnv32(key string) uint32 {
	hash := uint32(2166136261)
	prime := uint32(16777619)
	for i := 0; i < len(key); i++ {
		hash *= prime
		hash ^= uint32(key[i])
	}
	return hash
}