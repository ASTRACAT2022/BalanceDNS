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

// CacheItem represents an item in the cache.
type CacheItem struct {
	MsgBytes             []byte
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

// Cache is a thread-safe, sharded DNS cache with SLRU eviction policy and LMDB persistence.
type Cache struct {
	fastCache *FastCache
	lmdbEnv   *lmdb.Env
	lmdbDBI   lmdb.DBI
	metrics   *metrics.Metrics
	wg        sync.WaitGroup
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
		fastCache: NewFastCache(size, numShards),
		lmdbEnv:   env,
		lmdbDBI:   dbi,
		metrics:   m,
	}

	c.loadFromDB()

	return c
}

// Close gracefully closes the cache and its underlying LMDB environment.
func (c *Cache) Close() {
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

func (c *Cache) Get(key string) (*dns.Msg, bool, bool) {
	msgBytes, found, revalidate := c.fastCache.Get(key)
	if !found {
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBytes); err != nil {
		log.Printf("Failed to unpack message from in-memory cache for key %s: %v", key, err)
		c.metrics.IncrementCacheMisses()
		return nil, false, false
	}

	c.metrics.IncrementCacheHits()
	msg.Id = 0
	return msg, true, revalidate
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

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
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
	}()
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
