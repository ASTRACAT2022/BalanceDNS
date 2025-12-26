package cache

import (
	"dns-resolver/internal/metrics"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bmatsuo/lmdb-go/lmdb"
	"github.com/miekg/dns"
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
	// Allocate a buffer with enough space for all data.
	// 24 bytes for fixed-size metadata + length of the message bytes.
	buf := make([]byte, 24+f.MsgBytesLength)

	// Use binary.BigEndian to write fixed-size metadata directly to the byte slice.
	binary.BigEndian.PutUint64(buf[0:8], uint64(f.ExpirationUnix))
	binary.BigEndian.PutUint64(buf[8:16], uint64(f.StaleWhileRevalidateNanoseconds))
	binary.BigEndian.PutUint32(buf[16:20], f.MsgBytesLength)
	// The next 4 bytes are padding and are left as zero.

	// Copy the variable-length message bytes into the buffer.
	copy(buf[24:], f.MsgBytes)

	return buf, nil
}

// Unpack deserializes bytes into FixedSizeCacheItem
func (f *FixedSizeCacheItem) Unpack(data []byte) error {
	if len(data) < 24 { // Minimum length for the fixed-size metadata.
		return fmt.Errorf("data too short for unpacking")
	}

	// Read fixed-size metadata directly from the byte slice.
	f.ExpirationUnix = int64(binary.BigEndian.Uint64(data[0:8]))
	f.StaleWhileRevalidateNanoseconds = int64(binary.BigEndian.Uint64(data[8:16]))
	f.MsgBytesLength = binary.BigEndian.Uint32(data[16:20])
	// Bytes 20-24 are padding.

	// Check if the remaining data length matches the expected message length.
	if uint32(len(data)-24) < f.MsgBytesLength {
		return fmt.Errorf("message bytes length mismatch: expected %d, got %d", f.MsgBytesLength, len(data)-24)
	}

	// Slice the message bytes directly from the input data.
	f.MsgBytes = data[24 : 24+f.MsgBytesLength]

	return nil
}

// CacheItem represents an item in the cache.
type CacheItem struct {
	MsgBytes             []byte
	Expiration           time.Time
	StaleWhileRevalidate time.Duration
}

// Cache is a thread-safe, sharded DNS cache with SLRU eviction policy and LMDB persistence.
type Cache struct {
	fastCache    *FastCache
	lmdbEnv      *lmdb.Env
	lmdbDBI      lmdb.DBI
	metrics      *metrics.Metrics
	writeChan    chan *persistentCacheItemWrapper
	wg           sync.WaitGroup
	shutdownChan chan struct{}
}

type persistentCacheItemWrapper struct {
	key  string
	item *FixedSizeCacheItem
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
	err = env.SetMapSize(1 << 30) // 1GB
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

	c := &Cache{
		fastCache:    NewFastCache(size, numShards),
		lmdbEnv:      env,
		lmdbDBI:      dbi,
		metrics:      m,
		writeChan:    make(chan *persistentCacheItemWrapper, 1024),
		shutdownChan: make(chan struct{}),
	}

	c.loadFromDB()
	c.startWriter()

	return c
}

func (c *Cache) startWriter() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for itemWrapper := range c.writeChan {
			packedData, err := itemWrapper.item.Pack()
			if err != nil {
				log.Printf("Failed to pack cache item for key %s: %v", itemWrapper.key, err)
				continue
			}

			err = c.lmdbEnv.Update(func(txn *lmdb.Txn) error {
				return txn.Put(c.lmdbDBI, []byte(itemWrapper.key), packedData, 0)
			})
			if err != nil {
				c.metrics.IncrementLMDBErrors()
				log.Printf("Failed to write to LMDB for key %s: %v", itemWrapper.key, err)
			}
		}
	}()
}

// Close gracefully closes the cache and its underlying LMDB environment.
func (c *Cache) Close() {
	close(c.writeChan)
	c.wg.Wait()
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
			c.fastCache.Set(string(key), fItem.MsgBytes, expiration.Sub(time.Now()), time.Duration(fItem.StaleWhileRevalidateNanoseconds))
		}
		return nil
	})
	if err != nil {
		log.Printf("Error loading cache from LMDB: %v", err)
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

func (c *Cache) Get(key string) ([]byte, bool, bool) {
	msgBytes, found, revalidate := c.fastCache.Get(key)
	if !found {
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}
	c.metrics.IncrementCacheHits()
	return msgBytes, true, revalidate
}

func (c *Cache) Set(key string, msg *dns.Msg, swr time.Duration) {
	// Cache Success and NXDOMAIN
	if msg.Rcode == dns.RcodeServerFailure {
		return
	}

	ttl := getMinTTL(msg)
	expiration := time.Now().Add(time.Duration(ttl) * time.Second)

	packedMsg, err := msg.Pack()
	if err != nil {
		log.Printf("Failed to pack DNS message for key %s: %v", key, err)
		return
	}

	c.fastCache.Set(key, packedMsg, time.Duration(ttl)*time.Second, swr)

	fItem := &FixedSizeCacheItem{
		ExpirationUnix:                  expiration.Unix(),
		StaleWhileRevalidateNanoseconds: int64(swr),
		MsgBytesLength:                  uint32(len(packedMsg)),
		MsgBytes:                        packedMsg,
	}

	select {
	case c.writeChan <- &persistentCacheItemWrapper{key: key, item: fItem}:
	default:
		log.Printf("Warning: Cache write channel is full. Discarding write for key: %s", key)
	}
}

func Key(q dns.Question) string {
	var b strings.Builder
	// Approximate length: name + : + 5 + : + 5
	b.Grow(len(q.Name) + 12)
	b.WriteString(strings.ToLower(q.Name))
	b.WriteString(":")
	// Use AppendInt to avoid allocating a string
	buf := make([]byte, 0, 8)
	b.Write(strconv.AppendInt(buf, int64(q.Qtype), 10))
	b.WriteString(":")
	b.Write(strconv.AppendInt(buf, int64(q.Qclass), 10))
	return b.String()
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
	var minTTL uint32 = 0xFFFFFFFF
	found := false

	checkRR := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
				found = true
			}
		}
	}

	checkRR(msg.Answer)
	checkRR(msg.Ns)
	checkRR(msg.Extra)

	// If NXDOMAIN, try to find SOA in Authority section for negative TTL
	if msg.Rcode == dns.RcodeNameError && !found {
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				// RFC 2308: TTL for negative answer is min(SOA.TTL, SOA.Minttl)
				ttl := soa.Header().Ttl
				if soa.Minttl < ttl {
					ttl = soa.Minttl
				}
				return ttl
			}
		}
	}

	if !found || minTTL == 0xFFFFFFFF {
		return 60
	}
	if minTTL == 0 {
		return 60
	}

	return minTTL
}
