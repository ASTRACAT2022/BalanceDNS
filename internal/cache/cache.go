package cache

import (
	"bytes"
	"container/list"
	"dns-resolver/internal/metrics"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dns-resolver/internal/interfaces"

	"github.com/bmatsuo/lmdb-go/lmdb"
	"github.com/miekg/dns"
	"go.uber.org/atomic"
)

// persistentCacheItem is the struct that gets serialized to LMDB.
type persistentCacheItem struct {
	MsgBytes             []byte
	Expiration           time.Time
	StaleWhileRevalidate time.Duration
}

// FixedSizeCacheItem represents the cache item with fixed-size metadata
type FixedSizeCacheItem struct {
	ExpirationUnix          int64
	StaleWhileRevalidateNanoseconds int64
	MsgBytesLength          uint32
	MsgBytes                []byte
}

// Pack serializes the FixedSizeCacheItem into bytes
func (f *FixedSizeCacheItem) Pack() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Write fixed-size metadata
	err := binary.Write(buf, binary.BigEndian, f.ExpirationUnix)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, f.StaleWhileRevalidateNanoseconds)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.BigEndian, f.MsgBytesLength)
	if err != nil {
		return nil, err
	}
	
	// Write variable-length message bytes
	_, err = buf.Write(f.MsgBytes)
	if err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// Unpack deserializes bytes into FixedSizeCacheItem
func (f *FixedSizeCacheItem) Unpack(data []byte) error {
	if len(data) < 24 { // 8*3 bytes for the fixed-size fields
		return fmt.Errorf("data too short")
	}
	
	buf := bytes.NewReader(data)
	
	err := binary.Read(buf, binary.BigEndian, &f.ExpirationUnix)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.BigEndian, &f.StaleWhileRevalidateNanoseconds)
	if err != nil {
		return err
	}
	err = binary.Read(buf, binary.BigEndian, &f.MsgBytesLength)
	if err != nil {
		return err
	}
	
	remaining := buf.Len()
	if uint32(remaining) < f.MsgBytesLength {
		return fmt.Errorf("message bytes length mismatch")
	}
	
	f.MsgBytes = make([]byte, f.MsgBytesLength)
	_, err = buf.Read(f.MsgBytes)
	if err != nil {
		return err
	}
	
	return nil
}

// FastCacheItem represents a cache item in the high-performance cache
type FastCacheItem struct {
	MsgBytes             []byte
	Expiration           time.Time
	StaleWhileRevalidate time.Duration
}

// CacheItem represents an item in the cache.
type CacheItem struct {
	MsgBytes             []byte
	Question             dns.Question
	Expiration           time.Time
	StaleWhileRevalidate time.Duration
	element              *list.Element
	parentList           *list.List
}

// slruSegment represents one segment of the SLRU cache.
type slruSegment struct {
	sync.RWMutex
	items             map[string]*CacheItem
	probationList     *list.List
	protectedList     *list.List
	probationCapacity int
	protectedCapacity int
}

// fastCacheEntry contains the fast cache entry with expiration
type fastCacheEntry struct {
	item       *FastCacheItem
	expiration int64  // unix timestamp in nanoseconds
}

// Cache is a thread-safe, sharded DNS cache with SLRU eviction policy and LMDB persistence.
type Cache struct {
	shards        []*slruSegment
	numShards     uint32
	probationSize int
	protectedSize int
	resolver      interfaces.CacheResolver
	lmdbEnv       *lmdb.Env
	lmdbDBI       lmdb.DBI
	metrics       *metrics.Metrics
	// Performance counters
	hitCount      *atomic.Int64
	missCount     *atomic.Int64
	evictionCount *atomic.Int64
	// High-performance fast cache for most frequent lookups
	fastCache   sync.Map
	fastSize    int32
	maxFastSize int32
}

// NewCache creates and returns a new Cache with LMDB persistence.
func NewCache(size int, numShards int, lmdbPath string, m *metrics.Metrics) *Cache {
	if size <= 0 {
		size = DefaultCacheSize
	}
	if numShards <= 0 {
		numShards = DefaultShards
	}

	env, err := lmdb.NewEnv()
	if err != nil {
		log.Fatalf("Failed to create LMDB environment: %v", err)
	}

	if err := os.MkdirAll(lmdbPath, 0755); err != nil {
		log.Fatalf("Failed to create LMDB directory: %v", err)
	}

	err = env.SetMaxDBs(1)
	if err != nil {
		log.Fatalf("Failed to set max DBs for LMDB: %v", err)
	}
	// Increase LMDB map size for better performance
	err = env.SetMapSize(2 << 30) // 2GB
	if err != nil {
		log.Fatalf("Failed to set map size for LMDB: %v", err)
	}

	err = env.Open(lmdbPath, 0, 0644)
	if err != nil {
		log.Fatalf("Failed to open LMDB environment at %s: %v", lmdbPath, err)
	}

	var dbi lmdb.DBI
	err = env.Update(func(txn *lmdb.Txn) (err error) {
		dbi, err = txn.OpenDBI("cache", lmdb.Create)
		return err
	})
	if err != nil {
		log.Fatalf("Failed to open LMDB database: %v", err)
	}

	probationSize := int(float64(size) * SlruProbationFraction)
	protectedSize := size - probationSize

	shards := make([]*slruSegment, numShards)
	for i := 0; i < numShards; i++ {
		shards[i] = &slruSegment{
			items:             make(map[string]*CacheItem, probationSize/numShards + protectedSize/numShards),
			probationList:     list.New(),
			protectedList:     list.New(),
			probationCapacity: probationSize / numShards,
			protectedCapacity: protectedSize / numShards,
		}
	}

	c := &Cache{
		shards:        shards,
		numShards:     uint32(numShards),
		probationSize: probationSize,
		protectedSize: protectedSize,
		lmdbEnv:       env,
		lmdbDBI:       dbi,
		metrics:       m,
		hitCount:      atomic.NewInt64(0),
		missCount:     atomic.NewInt64(0),
		evictionCount: atomic.NewInt64(0),
		maxFastSize:   int32(size / 4), // Use 25% of total cache size for fast cache
	}

	// Load from persistent storage asynchronously for faster startup
	go c.loadFromDB()
	
	// Start the fast cache cleanup goroutine
	go c.cleanupFastCache()

	return c
}

// Close gracefully closes the cache and its underlying LMDB environment.
func (c *Cache) Close() {
	if c.lmdbEnv != nil {
		c.lmdbEnv.Close()
	}
}

func (c *Cache) loadFromDB() {
	err := c.lmdbEnv.View(func(txn *lmdb.Txn) error {
		cursor, err := txn.OpenCursor(c.lmdbDBI)
		if err != nil {
			return err
		}
		defer cursor.Close()

		for {
			key, val, err := cursor.Get(nil, nil, lmdb.Next)
			if lmdb.IsNotFound(err) {
				return nil
			}
			if err != nil {
				c.metrics.IncrementLMDBErrors()
				return err
			}

			var fItem FixedSizeCacheItem
			if err := fItem.Unpack(val); err != nil {
				c.metrics.IncrementLMDBErrors()
				log.Printf("Failed to unpack cache item for key %s: %v", string(key), err)
				continue
			}

			expiration := time.Unix(fItem.ExpirationUnix, 0)
			if time.Now().After(expiration) {
				continue
			}

			msg := new(dns.Msg)
			if err := msg.Unpack(fItem.MsgBytes); err != nil {
				c.metrics.IncrementLMDBErrors()
				log.Printf("Failed to unpack DNS message for key %s: %v", string(key), err)
				continue
			}

			c.metrics.IncrementLMDBCacheLoads()
			evictedKey := c.setInMemory(string(key), fItem.MsgBytes, msg.Question[0],
				time.Duration(fItem.StaleWhileRevalidateNanoseconds),
				expiration)
			if evictedKey != "" {
				c.metrics.IncrementCacheEvictions()
				c.deleteFromDB(evictedKey)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("Error loading cache from LMDB: %v", err)
	}
}

func (c *Cache) writeToDB(key string, msg *dns.Msg, expiration time.Time, swr time.Duration) {
	packedMsg, err := msg.Pack()
	if err != nil {
		log.Printf("Failed to pack DNS message for key %s: %v", key, err)
		return
	}

	fItem := FixedSizeCacheItem{
		ExpirationUnix:                  expiration.Unix(),
		StaleWhileRevalidateNanoseconds: int64(swr),
		MsgBytesLength:                  uint32(len(packedMsg)),
		MsgBytes:                        packedMsg,
	}

	packedData, err := fItem.Pack()
	if err != nil {
		log.Printf("Failed to pack cache item for key %s: %v", key, err)
		return
	}

	err = c.lmdbEnv.Update(func(txn *lmdb.Txn) error {
		return txn.Put(c.lmdbDBI, []byte(key), packedData, 0)
	})
	if err != nil {
		c.metrics.IncrementLMDBErrors()
		log.Printf("Failed to write to LMDB for key %s: %v", key, err)
	}
}

func (c *Cache) deleteFromDB(key string) {
	err := c.lmdbEnv.Update(func(txn *lmdb.Txn) error {
		return txn.Del(c.lmdbDBI, []byte(key), nil)
	})
	if err != nil {
		c.metrics.IncrementLMDBErrors()
		log.Printf("Failed to delete from LMDB for key %s: %v", key, err)
	}
}

func (c *Cache) Get(key string) (*dns.Msg, bool, bool) {
	// First check the fast cache
	if entry, ok := c.fastCache.Load(key); ok {
		fastEntry := entry.(*fastCacheEntry)
		now := time.Now().UnixNano()
		
		if now < fastEntry.expiration {
			// Fast cache hit
			msg := new(dns.Msg)
			if err := msg.Unpack(fastEntry.item.MsgBytes); err != nil {
				log.Printf("Failed to unpack message from fast cache for key %s: %v", key, err)
				c.fastCache.Delete(key)
				c.missCount.Inc()
				c.metrics.IncrementCacheMisses()
				return nil, false, false
			}
			
			c.hitCount.Inc()
			c.metrics.IncrementCacheHits()
			msg.Id = 0
			
			// Check if we need revalidation
			needsRevalidation := fastEntry.item.StaleWhileRevalidate > 0 && 
				now > (fastEntry.expiration - int64(fastEntry.item.StaleWhileRevalidate))
			
			return msg, true, needsRevalidation
		} else {
			// Entry expired, remove from fast cache
			c.fastCache.Delete(key)
			atomic.AddInt32(&c.fastSize, -1)
		}
	}

	// Fall back to SLRU cache
	shard := c.getShard(key)
	shard.RLock()  // Use read lock first for better performance
	
	item, found := shard.items[key]
	if !found {
		shard.RUnlock()
		c.missCount.Inc()
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	// Check expiration while holding read lock
	now := time.Now()
	isExpired := now.After(item.Expiration)
	
	if isExpired {
		shard.RUnlock()
		// If expired, upgrade to write lock to remove the item
		shard.Lock()
		defer shard.Unlock()
		
		// Double-check after acquiring write lock
		item, found = shard.items[key]
		if !found {
			c.missCount.Inc()
			c.metrics.IncrementCacheMisses()
			return nil, false, false
		}
		
		isExpired = now.After(item.Expiration)
		if isExpired {
			if item.StaleWhileRevalidate > 0 && now.Before(item.Expiration.Add(item.StaleWhileRevalidate)) {
				// Serve stale content but mark for revalidation
				msg := new(dns.Msg)
				if err := msg.Unpack(item.MsgBytes); err != nil {
					log.Printf("Failed to unpack stale message from in-memory cache for key %s: %v", key, err)
					evictedKey := shard.removeItem(item)
					if evictedKey != "" {
						c.evictionCount.Inc()
						c.metrics.IncrementCacheEvictions()
						c.deleteFromDB(evictedKey)
					}
					c.missCount.Inc()
					c.metrics.IncrementCacheMisses()
					return nil, false, false
				}
				
				// Add to fast cache if space allows
				c.addToFastCache(key, item.MsgBytes, item.Expiration, item.StaleWhileRevalidate)
				
				c.hitCount.Inc()
				c.metrics.IncrementCacheHits()
				msg.Id = 0
				return msg, true, true
			}
			
			// Remove expired item
			evictedKey := shard.removeItem(item)
			if evictedKey != "" {
				c.evictionCount.Inc()
				c.metrics.IncrementCacheEvictions()
				c.deleteFromDB(evictedKey)
			}
			c.missCount.Inc()
			c.metrics.IncrementCacheMisses()
			return nil, false, false
		}
	} else {
		shard.RUnlock()
		// Item is not expired, get it with proper locking
		shard.Lock()
		defer shard.Unlock()
		
		item, found = shard.items[key]
		if !found {
			c.missCount.Inc()
			c.metrics.IncrementCacheMisses()
			return nil, false, false
		}
		
		// Access the item (move to protected if in probation)
		evictedKey := shard.accessItem(item)
		if evictedKey != "" {
			c.evictionCount.Inc()
			c.metrics.IncrementCacheEvictions()
			c.deleteFromDB(evictedKey)
		}
		
		// Add to fast cache
		c.addToFastCache(key, item.MsgBytes, item.Expiration, item.StaleWhileRevalidate)
	}

	// Unpack the message after all checks are done
	msg := new(dns.Msg)
	if err := msg.Unpack(item.MsgBytes); err != nil {
		log.Printf("Failed to unpack message from in-memory cache for key %s: %v", key, err)
		// Remove corrupted item
		evictedKey := shard.removeItem(item)
		if evictedKey != "" {
			c.evictionCount.Inc()
			c.metrics.IncrementCacheEvictions()
			c.deleteFromDB(evictedKey)
		}
		c.missCount.Inc()
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	c.hitCount.Inc()
	c.metrics.IncrementCacheHits()
	msg.Id = 0
	return msg, true, false
}

// addToFastCache adds an entry to the fast cache
func (c *Cache) addToFastCache(key string, msgBytes []byte, expiration time.Time, swr time.Duration) {
	if atomic.LoadInt32(&c.fastSize) >= c.maxFastSize {
		return // Fast cache is full
	}

	item := &FastCacheItem{
		MsgBytes:             msgBytes,
		Expiration:           expiration,
		StaleWhileRevalidate: swr,
	}
	
	entry := &fastCacheEntry{
		item:       item,
		expiration: expiration.UnixNano(),
	}
	
	c.fastCache.Store(key, entry)
	atomic.AddInt32(&c.fastSize, 1)
}

func (c *Cache) Set(key string, msg *dns.Msg, swr time.Duration) {
	if msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeNameError {
		return
	}

	// Get TTL and pack message in parallel to optimize performance
	ttl := getMinTTL(msg)
	expiration := time.Now().Add(time.Duration(ttl) * time.Second)

	packedMsg, err := msg.Pack()
	if err != nil {
		log.Printf("Failed to pack DNS message for in-memory cache, key %s: %v", key, err)
		return
	}

	// Write to persistent storage asynchronously to avoid blocking
	go func() {
		c.writeToDB(key, msg, expiration, swr)
	}()

	evictedKey := c.setInMemory(key, packedMsg, msg.Question[0], swr, expiration)
	if evictedKey != "" && evictedKey != key {
		c.evictionCount.Inc()
		c.metrics.IncrementCacheEvictions()
		// Delete from DB asynchronously as well
		go func() {
			c.deleteFromDB(evictedKey)
		}()
	}
	
	// Add to fast cache
	c.addToFastCache(key, packedMsg, expiration, swr)
}

func (c *Cache) setInMemory(key string, msgBytes []byte, question dns.Question, swr time.Duration, expiration time.Time) string {
	shard := c.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	if existingItem, found := shard.items[key]; found {
		// Remove old entry from fast cache since content is being updated
		c.fastCache.Delete(key)
		atomic.AddInt32(&c.fastSize, -1)
		
		existingItem.MsgBytes = msgBytes
		existingItem.Question = question
		existingItem.Expiration = expiration
		existingItem.StaleWhileRevalidate = swr
		if existingItem.element != nil {
			if existingItem.parentList == shard.probationList {
				shard.probationList.Remove(existingItem.element)
				return shard.addProtected(key, existingItem)
			} else if existingItem.parentList == shard.protectedList {
				shard.protectedList.MoveToFront(existingItem.element)
			}
		}
		return ""
	}

	item := &CacheItem{
		MsgBytes:             msgBytes,
		Question:             question,
		Expiration:           expiration,
		StaleWhileRevalidate: swr,
	}
	return shard.addProbation(key, item)
}

func (s *slruSegment) addProbation(key string, item *CacheItem) string {
	var evictedKey string
	if s.probationList.Len() >= s.probationCapacity && s.probationCapacity > 0 {
		oldest := s.probationList.Back()
		if oldest != nil {
			evictedKey = oldest.Value.(string)
			delete(s.items, evictedKey)
			s.probationList.Remove(oldest)
		}
	}
	item.element = s.probationList.PushFront(key)
	item.parentList = s.probationList
	s.items[key] = item
	return evictedKey
}

func (s *slruSegment) addProtected(key string, item *CacheItem) string {
	var evictedKey string
	if s.protectedList.Len() >= s.protectedCapacity && s.protectedCapacity > 0 {
		oldest := s.protectedList.Back()
		if oldest != nil {
			keyToMove := oldest.Value.(string)
			itemToMove := s.items[keyToMove]
			s.protectedList.Remove(oldest)
			evictedKey = s.addProbation(keyToMove, itemToMove)
		}
	}
	item.element = s.protectedList.PushFront(key)
	item.parentList = s.protectedList
	s.items[key] = item
	return evictedKey
}

func (s *slruSegment) accessItem(item *CacheItem) string {
	if item.element == nil {
		return ""
	}

	if item.parentList == s.probationList {
		s.probationList.Remove(item.element)
		return s.addProtected(item.element.Value.(string), item)
	} else if item.parentList == s.protectedList {
		s.protectedList.MoveToFront(item.element)
	}
	return ""
}

func (s *slruSegment) removeItem(item *CacheItem) string {
	if item.element == nil {
		return ""
	}
	if item.parentList != nil {
		item.parentList.Remove(item.element)
	}
	key, ok := item.element.Value.(string)
	if !ok {
		return ""
	}
	delete(s.items, key)
	return key
}

func (c *Cache) SetResolver(r interfaces.CacheResolver) {
	c.resolver = r
}

func Key(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}

func (c *Cache) getShard(key string) *slruSegment {
	hash := fnv32(key)
	return c.shards[hash%c.numShards]
}

func fnv32(key string) uint32 {
	hash := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		hash *= 16777619
		hash ^= uint32(key[i])
	}
	return hash
}

func getMinTTL(msg *dns.Msg) uint32 {
	var minTTL uint32 = 0

	if len(msg.Answer) > 0 {
		minTTL = msg.Answer[0].Header().Ttl
		for _, rr := range msg.Answer {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	} else if len(msg.Ns) > 0 {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return soa.Minttl
			}
		}
	}

	if minTTL == 0 {
		return 60
	}

	return minTTL
}

func (c *Cache) GetCacheSize() (int, int) {
	var probationSize, protectedSize int
	for _, shard := range c.shards {
		shard.RLock()
		probationSize += shard.probationList.Len()
		protectedSize += shard.protectedList.Len()
		shard.RUnlock()
	}
	return probationSize, protectedSize
}

// GetCacheStats returns performance statistics
func (c *Cache) GetCacheStats() (hits int64, misses int64, evictions int64) {
	return c.hitCount.Load(), c.missCount.Load(), c.evictionCount.Load()
}

// ResetCacheStats resets the performance counters
func (c *Cache) ResetCacheStats() {
	c.hitCount.Store(0)
	c.missCount.Store(0)
	c.evictionCount.Store(0)
}

// cleanupFastCache periodically removes expired entries from the fast cache
func (c *Cache) cleanupFastCache() {
	ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
	defer ticker.Stop()
	
	for range ticker.C {
		cleanupCount := 0
		now := time.Now().UnixNano()
		
		c.fastCache.Range(func(key, value interface{}) bool {
			entry := value.(*fastCacheEntry)
			if now >= entry.expiration {
				c.fastCache.Delete(key)
				atomic.AddInt32(&c.fastSize, -1)
				cleanupCount++
			}
			return true
		})
		
		if cleanupCount > 0 {
			log.Printf("Cleaned up %d expired entries from fast cache", cleanupCount)
		}
	}
}

// Close properly closes the cache and its resources
func (c *Cache) Close() {
	if c.lmdbEnv != nil {
		c.lmdbEnv.Close()
	}
}
