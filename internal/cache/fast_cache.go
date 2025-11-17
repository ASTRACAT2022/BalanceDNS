package cache

import (
	"container/list"
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
	items    map[string]*list.Element
	lru      *list.List
	capacity int
}

type fastCacheItem struct {
	key        string
	msgBytes   []byte
	expiration time.Time
	swr        time.Duration
}

// NewFastCache creates a sharded in-memory FastCache with per-shard LRU eviction.
// If size or numShards are less than or equal to zero, package defaults are used.
// The total capacity is divided evenly across shards (capacity = size / numShards), and
// each shard is initialized with its own item map and LRU list.
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
			items:    make(map[string]*list.Element),
			lru:      list.New(),
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

// Get retrieves an item from the cache.
func (c *FastCache) Get(key string) ([]byte, bool, bool) {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if elem, hit := shard.items[key]; hit {
		item := elem.Value.(*fastCacheItem)
		now := time.Now()
		if now.After(item.expiration) {
			if item.swr > 0 && now.Before(item.expiration.Add(item.swr)) {
				shard.lru.MoveToFront(elem)
				return item.msgBytes, true, true
			}
			shard.lru.Remove(elem)
			delete(shard.items, key)
			return nil, false, false
		}
		shard.lru.MoveToFront(elem)
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

	if elem, hit := shard.items[key]; hit {
		shard.lru.MoveToFront(elem)
		item := elem.Value.(*fastCacheItem)
		item.msgBytes = msgBytes
		item.expiration = expiration
		item.swr = swr
		return
	}

	if shard.lru.Len() >= shard.capacity {
		elem := shard.lru.Back()
		if elem != nil {
			item := shard.lru.Remove(elem).(*fastCacheItem)
			delete(shard.items, item.key)
		}
	}

	item := &fastCacheItem{
		key:        key,
		msgBytes:   msgBytes,
		expiration: expiration,
		swr:        swr,
	}
	elem := shard.lru.PushFront(item)
	shard.items[key] = elem
}