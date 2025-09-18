package main

import (
	"container/list"
	"hash/fnv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry represents a single entry in the cache.
type CacheEntry struct {
	Key             string
	Msg             *dns.Msg
	Expiry          time.Time
	DNSSECValidated bool
}

// Shard is a part of the ShardedCache, protected by a mutex.
type Shard struct {
	entries    map[string]*list.Element
	ll         *list.List
	mu         sync.RWMutex
	maxEntries int
}

// ShardedCache implements a sharded, in-memory cache for DNS responses.
type ShardedCache struct {
	shards          []*Shard
	numShards       uint32
	stop            chan struct{}
	cleanupInterval time.Duration
}

// NewShardedCache creates a new ShardedCache.
func NewShardedCache(numShards int, maxEntriesPerShard int, cleanupInterval time.Duration) *ShardedCache {
	if numShards <= 0 {
		numShards = 32
	}
	if maxEntriesPerShard <= 0 {
		maxEntriesPerShard = 1000
	}
	shards := make([]*Shard, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &Shard{
			entries:    make(map[string]*list.Element),
			ll:         list.New(),
			maxEntries: maxEntriesPerShard,
		}
	}
	cache := &ShardedCache{
		shards:          shards,
		numShards:       uint32(numShards),
		stop:            make(chan struct{}),
		cleanupInterval: cleanupInterval,
	}
	cache.startCleanup()
	return cache
}

// Get retrieves a DNS message from the cache.
func (c *ShardedCache) Get(key string) (*dns.Msg, bool, bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	element, found := shard.entries[key]
	if !found {
		return nil, false, false
	}

	entry := element.Value.(*CacheEntry)
	if time.Now().After(entry.Expiry) {
		shard.ll.Remove(element)
		delete(shard.entries, key)
		return nil, false, false
	}

	shard.ll.MoveToFront(element)
	return entry.Msg, true, entry.DNSSECValidated
}

// Set adds a DNS message to the cache.
func (c *ShardedCache) Set(key string, msg *dns.Msg, ttl time.Duration, dnssecValidated bool) {
	shard := c.getShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if element, found := shard.entries[key]; found {
		shard.ll.MoveToFront(element)
		entry := element.Value.(*CacheEntry)
		entry.Msg = msg
		entry.Expiry = time.Now().Add(ttl)
		entry.DNSSECValidated = dnssecValidated
		return
	}

	if shard.ll.Len() >= shard.maxEntries {
		lruElement := shard.ll.Back()
		if lruElement != nil {
			lruEntry := shard.ll.Remove(lruElement).(*CacheEntry)
			delete(shard.entries, lruEntry.Key)
		}
	}

	entry := &CacheEntry{
		Key:             key,
		Msg:             msg,
		Expiry:          time.Now().Add(ttl),
		DNSSECValidated: dnssecValidated,
	}
	element := shard.ll.PushFront(entry)
	shard.entries[key] = element
}

// Stop stops the background cleanup goroutines.
func (c *ShardedCache) Stop() {
	close(c.stop)
}

// getShard determines which shard a key belongs to.
func (c *ShardedCache) getShard(key string) *Shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()%c.numShards]
}

// startCleanup starts a goroutine for each shard to periodically remove expired entries.
func (c *ShardedCache) startCleanup() {
	for i := 0; i < int(c.numShards); i++ {
		go c.shards[i].cleanup(c.cleanupInterval, c.stop)
	}
}

// cleanup removes expired entries from the shard.
func (s *Shard) cleanup(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			element := s.ll.Front()
			for element != nil {
				next := element.Next()
				entry := element.Value.(*CacheEntry)
				if now.After(entry.Expiry) {
					s.ll.Remove(element)
					delete(s.entries, entry.Key)
				}
				element = next
			}
			s.mu.Unlock()
		case <-stop:
			return
		}
	}
}