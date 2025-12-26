package cache

import (
	"hash/maphash"
	"sync"
	"time"
)

// FastCache is a sharded in-memory cache with LRU eviction.
type FastCache struct {
	shards    []*fastCacheShard
	numShards uint32
	seed      maphash.Seed
}

// fastCacheShard uses a custom LRU implementation to minimize GC pressure.
type fastCacheShard struct {
	sync.Mutex
	items    map[string]*entry // Map from key to list node
	head     *entry            // MRU
	tail     *entry            // LRU
	capacity int
	size     int
}

// entry is a node in the doubly linked list.
type entry struct {
	key        string
	msgBytes   []byte
	expiration time.Time
	swr        time.Duration
	prev       *entry
	next       *entry
}

// entryPool reuses entry objects to reduce GC pressure.
var entryPool = &sync.Pool{
	New: func() interface{} {
		return &entry{}
	},
}

// NewFastCache creates a new FastCache.
func NewFastCache(size int, numShards int) *FastCache {
	if size <= 0 {
		size = DefaultCacheSize
	}
	if numShards <= 0 {
		numShards = DefaultShards
	}

	shards := make([]*fastCacheShard, numShards)
	shardSize := size / numShards
	for i := 0; i < numShards; i++ {
		shards[i] = &fastCacheShard{
			items:    make(map[string]*entry),
			capacity: shardSize,
		}
	}
	return &FastCache{
		shards:    shards,
		numShards: uint32(numShards),
		seed:      maphash.MakeSeed(),
	}
}

func (c *FastCache) getShard(key string) *fastCacheShard {
	var h maphash.Hash
	h.SetSeed(c.seed)
	h.WriteString(key)
	hash := h.Sum64()
	return c.shards[hash%uint64(c.numShards)]
}

// Get retrieves an item from the cache.
func (c *FastCache) Get(key string) ([]byte, bool, bool) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if ent, hit := shard.items[key]; hit {
		now := time.Now()
		if now.After(ent.expiration) {
			// Check if stale-while-revalidate applies
			if ent.swr > 0 && now.Before(ent.expiration.Add(ent.swr)) {
				shard.moveToFront(ent)
				return ent.msgBytes, true, true
			}
			// Expired and no SWR, remove it
			shard.remove(ent)
			return nil, false, false
		}
		shard.moveToFront(ent)
		return ent.msgBytes, true, false
	}
	return nil, false, false
}

// Set adds an item to the cache.
func (c *FastCache) Set(key string, msgBytes []byte, ttl time.Duration, swr time.Duration) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	expiration := time.Now().Add(ttl)

	if ent, hit := shard.items[key]; hit {
		shard.moveToFront(ent)
		ent.msgBytes = msgBytes
		ent.expiration = expiration
		ent.swr = swr
		return
	}

	// Evict if full
	if shard.size >= shard.capacity {
		shard.removeOldest()
	}

	// Add new item
	ent := entryPool.Get().(*entry)
	ent.key = key
	ent.msgBytes = msgBytes
	ent.expiration = expiration
	ent.swr = swr
	ent.prev = nil
	ent.next = nil

	shard.addToFront(ent)
	shard.items[key] = ent
}

// addToFront adds an entry to the front of the list (MRU)
func (s *fastCacheShard) addToFront(ent *entry) {
	if s.head == nil {
		s.head = ent
		s.tail = ent
		ent.prev = nil
		ent.next = nil
	} else {
		ent.next = s.head
		ent.prev = nil
		s.head.prev = ent
		s.head = ent
	}
	s.size++
}

// moveToFront moves an existing entry to the front
func (s *fastCacheShard) moveToFront(ent *entry) {
	if s.head == ent {
		return
	}

	// Unlink
	if ent.prev != nil {
		ent.prev.next = ent.next
	}
	if ent.next != nil {
		ent.next.prev = ent.prev
	}
	if s.tail == ent {
		s.tail = ent.prev
	}

	// Link to front
	ent.next = s.head
	ent.prev = nil
	if s.head != nil {
		s.head.prev = ent
	}
	s.head = ent
}

// remove removes an entry from the list and map
func (s *fastCacheShard) remove(ent *entry) {
	delete(s.items, ent.key)

	if ent.prev != nil {
		ent.prev.next = ent.next
	} else {
		s.head = ent.next
	}

	if ent.next != nil {
		ent.next.prev = ent.prev
	} else {
		s.tail = ent.prev
	}

	s.size--

	// Clear and return to pool
	ent.key = ""
	ent.msgBytes = nil
	ent.prev = nil
	ent.next = nil
	entryPool.Put(ent)
}

// removeOldest removes the LRU item
func (s *fastCacheShard) removeOldest() {
	if s.tail != nil {
		s.remove(s.tail)
	}
}
