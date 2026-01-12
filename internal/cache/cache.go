package cache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
	bolt "go.etcd.io/bbolt"
)

// persistentCacheItem is the struct that gets serialized to BoltDB.
type persistentCacheItem struct {
	MsgBytes             []byte
	Expiration           time.Time
	StaleWhileRevalidate time.Duration
}

const (
	PersistenceWorkers   = 5
	PersistenceQueueSize = 10000
	BoltBucketName       = "dns_cache"
)

// FixedSizeCacheItem represents the cache item with fixed-size metadata
type FixedSizeCacheItem struct {
	Key                             string
	ExpirationUnix                  int64
	StaleWhileRevalidateNanoseconds int64
	MsgBytesLength                  uint32
	MsgBytes                        []byte
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

// Cache is a thread-safe, sharded DNS cache with SLRU eviction policy and BoltDB persistence.
type Cache struct {
	fastCache *FastCache
	db        *bolt.DB
	metrics   *metrics.Metrics
	wg        sync.WaitGroup
	persistCh chan *FixedSizeCacheItem
}

// NewCache creates and returns a new Cache with BoltDB persistence.
func NewCache(size int, numShards int, dbPath string, m *metrics.Metrics) *Cache {
	if size <= 0 {
		size = DefaultCacheSize
	}
	if numShards <= 0 {
		numShards = DefaultShards
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Failed to create cache directory: %v", err)
	}

	// Open BoltDB
	// Set strict mode false? No, just standard open.
	// We want fast writes, maybe Sync=false? For DNS cache durability isn't critical.
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second, NoSync: true})
	if err != nil {
		log.Fatalf("Failed to open BoltDB at %s: %v", dbPath, err)
	}

	// Create bucket if not exists
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(BoltBucketName))
		return err
	})
	if err != nil {
		log.Fatalf("Failed to create BoltDB bucket: %v", err)
	}

	c := &Cache{
		fastCache: NewFastCache(size, numShards),
		db:        db,
		metrics:   m,
		persistCh: make(chan *FixedSizeCacheItem, PersistenceQueueSize),
	}

	log.Println("Cache initialized with lazy loading (BoltDB backing).")

	// Start persistence workers
	for i := 0; i < PersistenceWorkers; i++ {
		c.wg.Add(1)
		go c.persistWorker()
	}

	return c
}

// Close gracefully closes the cache and its underlying database.
func (c *Cache) Close() {
	close(c.persistCh)
	c.wg.Wait()
	if c.db != nil {
		c.db.Close()
	}
}

func (c *Cache) deleteFromDB(key string) {
	err := c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BoltBucketName))
		return b.Delete([]byte(key))
	})
	if err != nil {
		c.metrics.IncrementLMDBErrors() // Reuse metric or create new one? Reuse is fine.
		log.Printf("Failed to delete from BoltDB for key %s: %v", key, err)
	}
}

func (c *Cache) Get(key string) (*dns.Msg, bool, bool) {
	// 1. Check FastCache (RAM)
	msgBytes, found, revalidate := c.fastCache.Get(key)
	if found {
		msg := new(dns.Msg)
		if err := msg.Unpack(msgBytes); err == nil {
			c.metrics.IncrementCacheHits()
			msg.Id = 0
			return msg, true, revalidate
		}
	}

	// 2. Check BoltDB (Disk) - Lazy Loading
	var fItem FixedSizeCacheItem
	var valCopy []byte

	err := c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BoltBucketName))
		val := b.Get([]byte(key))
		if val == nil {
			return bolt.ErrBucketNotFound // Or just nil
		}
		// Must copy value because it's only valid inside transaction
		valCopy = make([]byte, len(val))
		copy(valCopy, val)
		return nil
	})

	if valCopy == nil {
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	if err != nil && err != bolt.ErrBucketNotFound {
		c.metrics.IncrementLMDBErrors()
		c.metrics.IncrementCacheMisses()
		log.Printf("BoltDB get error for key %s: %v", key, err)
		return nil, false, false
	}

	if err := fItem.Unpack(valCopy); err != nil {
		c.metrics.IncrementLMDBErrors()
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	// 3. Check Expiration
	expiration := time.Unix(fItem.ExpirationUnix, 0)
	if time.Now().After(expiration) {
		// Lazy Delete
		go c.deleteFromDB(key)
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	// 4. Unpack and Promote to RAM
	msg := new(dns.Msg)
	if err := msg.Unpack(fItem.MsgBytes); err != nil {
		log.Printf("Failed to unpack DNS message from disk for key %s: %v", key, err)
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	// Promote to FastCache
	c.metrics.IncrementLMDBCacheLoads()
	c.fastCache.Set(key, fItem.MsgBytes, time.Until(expiration), time.Duration(fItem.StaleWhileRevalidateNanoseconds))

	c.metrics.IncrementCacheHits()
	msg.Id = 0
	return msg, true, false
}

func (c *Cache) Set(key string, msg *dns.Msg, swr time.Duration) {
	if msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeNameError {
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

	// Non-blocking write to persistence channel
	select {
	case c.persistCh <- &FixedSizeCacheItem{
		Key:                             key,
		ExpirationUnix:                  expiration.Unix(),
		StaleWhileRevalidateNanoseconds: int64(swr),
		MsgBytesLength:                  uint32(len(packedMsg)),
		MsgBytes:                        packedMsg,
	}:
		// Successfully queued
	default:
		c.metrics.IncrementDroppedCacheWrites()
	}
}

func Key(q dns.Question) string {
	return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
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
