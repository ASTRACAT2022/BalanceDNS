package cache

import (
	"sync"
	"time"
)

// FastCache is a sharded in-memory cache with LRU eviction.
type FastCache struct {
	shards    []*fastCacheShard
	numShards uint32
}

type fastCacheShard struct {
	sync.Mutex
	items    map[string]*fastCacheItem
	head     *fastCacheItem // MRU
	tail     *fastCacheItem // LRU
	size     int
	capacity int
}

type fastCacheItem struct {
	key        string
	msgBytes   []byte
	expiration time.Time
	swr        time.Duration
	prev       *fastCacheItem
	next       *fastCacheItem
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
			items:    make(map[string]*fastCacheItem),
			capacity: shardSize,
		}
	}
	return &FastCache{
		shards:    shards,
		numShards: uint32(numShards),
	}
}

func (c *FastCache) getShard(key string) *fastCacheShard {
	hash := fnv32(key)
	return c.shards[hash%c.numShards]
}

// moveToFront moves the item to the front of the list (MRU).
func (s *fastCacheShard) moveToFront(item *fastCacheItem) {
	if s.head == item {
		return
	}

	// Remove from current position
	if item.prev != nil {
		item.prev.next = item.next
	}
	if item.next != nil {
		item.next.prev = item.prev
	}
	if item == s.tail {
		s.tail = item.prev
	}

	// Insert at head
	item.next = s.head
	item.prev = nil
	if s.head != nil {
		s.head.prev = item
	}
	s.head = item
	if s.tail == nil {
		s.tail = item
	}
}

// remove removes the item from the list.
func (s *fastCacheShard) remove(item *fastCacheItem) {
	if item.prev != nil {
		item.prev.next = item.next
	} else {
		s.head = item.next
	}
	if item.next != nil {
		item.next.prev = item.prev
	} else {
		s.tail = item.prev
	}
	item.prev = nil
	item.next = nil
	s.size--
}

// pushFront adds an item to the front.
func (s *fastCacheShard) pushFront(item *fastCacheItem) {
	item.next = s.head
	item.prev = nil
	if s.head != nil {
		s.head.prev = item
	}
	s.head = item
	if s.tail == nil {
		s.tail = item
	}
	s.size++
}

// removeTail removes the LRU item.
func (s *fastCacheShard) removeTail() *fastCacheItem {
	if s.tail == nil {
		return nil
	}
	item := s.tail
	s.remove(item)
	return item
}

// Get retrieves an item from the cache.
func (c *FastCache) Get(key string) ([]byte, bool, bool) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if item, hit := shard.items[key]; hit {
		now := time.Now()
		if now.After(item.expiration) {
			if item.swr > 0 && now.Before(item.expiration.Add(item.swr)) {
				shard.moveToFront(item)
				return item.msgBytes, true, true
			}
			shard.remove(item)
			delete(shard.items, key)
			return nil, false, false
		}
		shard.moveToFront(item)
		return item.msgBytes, true, false
	}
	return nil, false, false
}

// Set adds an item to the cache.
func (c *FastCache) Set(key string, msgBytes []byte, ttl time.Duration, swr time.Duration) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	expiration := time.Now().Add(ttl)

	if item, hit := shard.items[key]; hit {
		shard.moveToFront(item)
		item.msgBytes = msgBytes
		item.expiration = expiration
		item.swr = swr
		return
	}

	if shard.size >= shard.capacity {
		removed := shard.removeTail()
		if removed != nil {
			delete(shard.items, removed.key)
		}
	}

	item := &fastCacheItem{
		key:        key,
		msgBytes:   msgBytes,
		expiration: expiration,
		swr:        swr,
	}
	shard.pushFront(item)
	shard.items[key] = item
}
