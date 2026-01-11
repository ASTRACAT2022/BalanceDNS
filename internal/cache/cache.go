package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"go.etcd.io/bbolt"
)

/* =========================
   Types
========================= */

type PolicyAction int

const (
	ActionPass PolicyAction = iota
	ActionBlock
	ActionRewrite
)

type Decision struct {
	Action   PolicyAction
	Data     string
	Upstream string
}

type diskEntry struct {
	Decision Decision
	ExpireAt int64
}

type writeReq struct {
	key   string
	entry diskEntry
}

/* =========================
   Cache
========================= */

type Cache struct {
	l1 *ristretto.Cache
	l2 *bbolt.DB

	writes chan writeReq
	wg     sync.WaitGroup
	stop   chan struct{}
}

var bucketName = []byte("decisions")

/* =========================
   Init
========================= */

func NewCache(ramMB int, dbPath string) (*Cache, error) {
	l1, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 1e6,
		MaxCost:     int64(ramMB) * 1024 * 1024,
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}

	// L2: BoltDB
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		l1.Close()
		return nil, fmt.Errorf("failed to create cache dir: %v", err)
	}

	l2, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		l1.Close()
		return nil, fmt.Errorf("failed to open l2 db: %v", err)
	}

	// Create bucket
	err = l2.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		l2.Close()
		l1.Close()
		return nil, err
	}

	c := &Cache{
		l1:     l1,
		l2:     l2,
		writes: make(chan writeReq, 1024),
		stop:   make(chan struct{}),
	}

	c.startWriter()
	return c, nil
}

/* =========================
   Writer loop
========================= */

func (c *Cache) startWriter() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case req := <-c.writes:
				_ = c.l2.Update(func(tx *bbolt.Tx) error {
					b := tx.Bucket(bucketName)
					data, _ := json.Marshal(req.entry)
					return b.Put([]byte(req.key), data)
				})
			case <-c.stop:
				return
			}
		}
	}()
}

/* =========================
   Get
========================= */

func (c *Cache) Get(key string) (*Decision, bool) {
	// L1
	if v, ok := c.l1.Get(key); ok {
		if d, ok := v.(*Decision); ok {
			return d, true
		}
	}

	// L2
	var entry diskEntry
	err := c.l2.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		raw := b.Get([]byte(key))
		if raw == nil {
			return errors.New("miss")
		}
		return json.Unmarshal(raw, &entry)
	})
	if err != nil {
		return nil, false
	}

	if time.Now().Unix() > entry.ExpireAt {
		_ = c.delete(key)
		return nil, false
	}

	// promote to L1
	c.l1.SetWithTTL(key, &entry.Decision, 1, 30*time.Second)
	return &entry.Decision, true
}

/* =========================
   Set
========================= */

func (c *Cache) Set(key string, d *Decision, ttl time.Duration) {
	exp := time.Now().Add(ttl).Unix()

	c.l1.SetWithTTL(key, d, 1, ttl)

	select {
	case c.writes <- writeReq{
		key: key,
		entry: diskEntry{
			Decision: *d,
			ExpireAt: exp,
		},
	}:
	default:
		// drop on overload — L1 still works
	}
}

/* =========================
   Delete expired
========================= */

func (c *Cache) delete(key string) error {
	return c.l2.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete([]byte(key))
	})
}

/* =========================
   Close
========================= */

func (c *Cache) Close() {
	close(c.stop)
	c.wg.Wait()

	c.l1.Close()
	c.l2.Close()
}
