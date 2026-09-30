package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"balancedns/internal/metrics"

	"github.com/miekg/dns"
)

const maxShards = 64

type key struct {
	fqdn   string
	qtype  uint16
	qclass uint16
}

type entry struct {
	key         key
	message     *dns.Msg
	expiresAt   time.Time
	storedAt    time.Time
	originalTTL time.Duration
	hits        uint64
	element     *list.Element
}

type shard struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[key]*entry
}

type Cache struct {
	maxTTL  time.Duration
	shards  []shard
	metrics *metrics.Provider

	// entries is a running count of cached items, updated atomically on
	// insert/evict/expire. It is O(1) and avoids locking all shards from
	// within a shard-critical section (which would deadlock).
	entries           atomic.Int64
	staleTTL          time.Duration
	persistentDir     string
	persistQ          chan diskWrite
	persistDone       chan struct{}
	persistPruneStop  chan struct{}
	persistPruneDone  chan struct{}
	persistentMaxSize int64
	refreshMu         sync.Mutex
	refreshing        map[key]bool
	refreshFailures   map[key]int
	refreshAfter      map[key]time.Time
	refreshSem        chan struct{}
	prefetchThreshold int
	retryMin          time.Duration
	retryMax          time.Duration
	refreshWG         sync.WaitGroup
	closed            bool
	closeOnce         sync.Once
}

type diskRecord struct {
	FQDN        string    `json:"fqdn"`
	QType       uint16    `json:"qtype"`
	QClass      uint16    `json:"qclass"`
	StoredAt    time.Time `json:"stored_at"`
	OriginalTTL int64     `json:"original_ttl_ns"`
	Wire        []byte    `json:"wire"`
}
type diskWrite struct {
	path string
	data []byte
}

func New(capacity int, minTTLSeconds, maxTTLSeconds uint32) *Cache {
	return NewWithMetrics(capacity, minTTLSeconds, maxTTLSeconds, nil)
}

func NewWithMetrics(capacity int, _ uint32, maxTTLSeconds uint32, m *metrics.Provider) *Cache {
	if capacity <= 0 {
		capacity = 1
	}

	shardCount := chooseShardCount(capacity)
	shards := make([]shard, shardCount)
	for i := range shards {
		shards[i] = shard{
			cap:   shardCapacity(capacity, shardCount, i),
			ll:    list.New(),
			items: make(map[key]*entry),
		}
	}

	return &Cache{
		maxTTL:          time.Duration(maxTTLSeconds) * time.Second,
		shards:          shards,
		metrics:         m,
		staleTTL:        30 * time.Second,
		refreshing:      make(map[key]bool),
		refreshFailures: make(map[key]int),
		refreshAfter:    make(map[key]time.Time),
		retryMin:        time.Second,
		retryMax:        30 * time.Minute,
	}
}

func (c *Cache) Configure(staleTTL time.Duration, prefetchThreshold, workers int) {
	if staleTTL >= 0 {
		c.staleTTL = staleTTL
	}
	if prefetchThreshold > 0 {
		c.prefetchThreshold = prefetchThreshold
	}
	if workers > 0 {
		c.refreshSem = make(chan struct{}, workers)
	}
}

func (c *Cache) ConfigureRetry(minDelay, maxDelay time.Duration) {
	if minDelay > 0 {
		c.retryMin = minDelay
	}
	if maxDelay >= c.retryMin {
		c.retryMax = maxDelay
	}
}

func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	msg, _, ok := c.GetState(q)
	return msg, ok
}

// GetState returns a copy of a positive response and whether it remains fresh.
// Expired entries stay resident as Last Known Good until normal LRU eviction.
func (c *Cache) GetState(q dns.Question) (*dns.Msg, bool, bool) {
	if c.metrics != nil {
		c.metrics.DNSCacheRequests.Inc()
	}
	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]

	s.mu.Lock()
	now := time.Now()
	item, ok := s.items[k]
	if !ok {
		s.mu.Unlock()
		c.incMiss()
		return nil, false, false
	}
	s.ll.MoveToFront(item.element)
	item.hits++
	message := item.message.Copy()
	fresh := now.Before(item.expiresAt)
	if fresh {
		decrementMessageTTL(message, uint32(now.Sub(item.storedAt)/time.Second))
	} else if c.staleTTL > 0 {
		setMessageTTL(message, uint32(c.staleTTL/time.Second))
	}
	s.mu.Unlock()
	if c.metrics != nil {
		c.metrics.DNSCacheL1Hits.Inc()
	}
	if c.metrics != nil {
		if fresh {
			c.metrics.DNSCacheFreshHits.Inc()
		} else {
			c.metrics.DNSCacheStaleHits.Inc()
		}
	}

	// Responses are copied while holding the shard lock so an atomic replacement
	// cannot expose a partially modified packet to a reader.
	c.incHit()
	return message, fresh, true
}

// Set stores response in the cache. The caller must not mutate response after
// Set returns: the cache retains a reference to it (no defensive copy) to avoid
// a double deep-copy on the hot path. Get always returns a deep copy, so the
// stored message is never exposed directly to readers.
func (c *Cache) Set(q dns.Question, response *dns.Msg) {
	if response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
		return
	}

	ttl := c.extractTTL(response)
	if ttl <= 0 {
		return
	}

	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]
	storedAt := time.Now()
	expiresAt := storedAt.Add(ttl)

	s.mu.Lock()
	if current, ok := s.items[k]; ok {
		current.message = response
		current.expiresAt = expiresAt
		current.storedAt = storedAt
		current.originalTTL = ttl
		s.ll.MoveToFront(current.element)
		s.mu.Unlock()
		c.enqueuePersist(k, response, storedAt, ttl)
		return
	}

	elem := s.ll.PushFront(k)
	s.items[k] = &entry{
		key:         k,
		message:     response,
		expiresAt:   expiresAt,
		storedAt:    storedAt,
		originalTTL: ttl,
		element:     elem,
	}

	evicted := len(s.items) > s.cap
	if evicted {
		s.evictOldest()
		c.entries.Add(-1)
	}
	c.entries.Add(1)
	s.mu.Unlock()

	if evicted {
		// The eviction was accounted for under the lock; report it after unlock.
		c.incEviction()
	}
	c.reportEntries()
	c.enqueuePersist(k, response, storedAt, ttl)
}

// GetPersistent lazily restores one L2 record into RAM. Corrupt or unavailable
// records are treated as misses and never affect resolver availability.
func (c *Cache) GetPersistent(q dns.Question) (*dns.Msg, bool, bool) {
	if c.persistentDir == "" {
		if c.metrics != nil {
			c.metrics.DNSCacheMisses.Inc()
		}
		return nil, false, false
	}
	k := makeKey(q)
	b, err := os.ReadFile(c.recordPath(k))
	if err != nil {
		if c.metrics != nil {
			c.metrics.DNSCacheMisses.Inc()
		}
		return nil, false, false
	}
	var rec diskRecord
	if json.Unmarshal(b, &rec) != nil || rec.FQDN != k.fqdn || rec.QType != k.qtype || rec.QClass != k.qclass || rec.OriginalTTL <= 0 {
		if c.metrics != nil {
			c.metrics.DNSCacheMisses.Inc()
		}
		return nil, false, false
	}
	msg := new(dns.Msg)
	if msg.Unpack(rec.Wire) != nil || msg.Rcode != dns.RcodeSuccess || len(msg.Answer) == 0 {
		if c.metrics != nil {
			c.metrics.DNSCacheMisses.Inc()
		}
		return nil, false, false
	}
	if c.metrics != nil {
		c.metrics.DNSCacheL2Hits.Inc()
	}
	_ = os.Chtimes(c.recordPath(k), time.Now(), time.Now())
	ttl := time.Duration(rec.OriginalTTL)
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	c.setLoaded(k, msg, rec.StoredAt, ttl)
	clientMsg := msg.Copy()
	fresh := time.Now().Before(rec.StoredAt.Add(ttl))
	if fresh {
		decrementMessageTTL(clientMsg, uint32(time.Since(rec.StoredAt)/time.Second))
	} else if c.staleTTL > 0 {
		setMessageTTL(clientMsg, uint32(c.staleTTL/time.Second))
	}
	return clientMsg, fresh, true
}

func (c *Cache) setLoaded(k key, msg *dns.Msg, storedAt time.Time, ttl time.Duration) {
	s := &c.shards[c.shardIndex(k)]
	s.mu.Lock()
	if cur := s.items[k]; cur != nil {
		s.mu.Unlock()
		return
	}
	e := s.ll.PushFront(k)
	s.items[k] = &entry{key: k, message: msg, storedAt: storedAt, originalTTL: ttl, expiresAt: storedAt.Add(ttl), element: e}
	if len(s.items) > s.cap {
		s.evictOldest()
		c.entries.Add(-1)
		c.incEviction()
	}
	c.entries.Add(1)
	s.mu.Unlock()
	c.reportEntries()
}

func (c *Cache) SetPersistent(path string) error {
	return c.SetPersistentLimit(path, 0)
}

func (c *Cache) SetPersistentLimit(path string, maxBytes int64) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	c.persistentDir = path
	c.persistentMaxSize = maxBytes
	c.persistQ = make(chan diskWrite, 4096)
	c.persistDone = make(chan struct{})
	go func() {
		defer close(c.persistDone)
		for w := range c.persistQ {
			writeDiskRecord(w)
		}
	}()
	if maxBytes > 0 {
		c.persistPruneStop = make(chan struct{})
		c.persistPruneDone = make(chan struct{})
		go func() {
			defer close(c.persistPruneDone)
			t := time.NewTicker(10 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-c.persistPruneStop:
					return
				case <-t.C:
					c.prunePersistent()
				}
			}
		}()
	}
	return nil
}

func (c *Cache) Close() {
	c.closeOnce.Do(func() {
		if c.persistPruneStop != nil {
			close(c.persistPruneStop)
			<-c.persistPruneDone
		}
		c.refreshMu.Lock()
		c.closed = true
		c.refreshMu.Unlock()
		c.refreshWG.Wait()
		if c.persistQ != nil {
			close(c.persistQ)
			<-c.persistDone
		}
	})
}

func writeDiskRecord(w diskWrite) {
	var next diskRecord
	if json.Unmarshal(w.data, &next) != nil {
		return
	}
	if previous, err := os.ReadFile(w.path); err == nil {
		var old diskRecord
		if json.Unmarshal(previous, &old) == nil && old.StoredAt.After(next.StoredAt) {
			return
		}
	}
	if os.MkdirAll(filepath.Dir(w.path), 0o750) != nil {
		return
	}
	tmp := w.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	if _, err = f.Write(w.data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp, w.path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return
	}
	if dir, err := os.Open(filepath.Dir(w.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
}

type diskFile struct {
	path     string
	size     int64
	modified time.Time
}

func (c *Cache) prunePersistent() {
	var files []diskFile
	var total int64
	_ = filepath.Walk(c.persistentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		files = append(files, diskFile{path: path, size: info.Size(), modified: info.ModTime()})
		total += info.Size()
		return nil
	})
	if total <= c.persistentMaxSize {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modified.Before(files[j].modified) })
	for _, f := range files {
		if total <= c.persistentMaxSize {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
		}
	}
}

func (c *Cache) recordPath(k key) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", k.fqdn, k.qtype, k.qclass)))
	h := hex.EncodeToString(sum[:])
	return filepath.Join(c.persistentDir, h[:2], h+".json")
}
func (c *Cache) enqueuePersist(k key, msg *dns.Msg, storedAt time.Time, ttl time.Duration) {
	if c.persistQ == nil {
		return
	}
	wire, err := msg.Pack()
	if err != nil {
		return
	}
	data, err := json.Marshal(diskRecord{FQDN: k.fqdn, QType: k.qtype, QClass: k.qclass, StoredAt: storedAt, OriginalTTL: int64(ttl), Wire: wire})
	if err == nil {
		c.persistQ <- diskWrite{path: c.recordPath(k), data: data}
	}
}

// Refresh starts at most one background update for a key and applies bounded
// exponential backoff after failures. The caller returns its cached answer first.
func (c *Cache) Refresh(q dns.Question, resolve func() (*dns.Msg, error)) bool {
	k := makeKey(q)
	now := time.Now()
	c.refreshMu.Lock()
	if c.closed || c.refreshing[k] || now.Before(c.refreshAfter[k]) {
		c.refreshMu.Unlock()
		return false
	}
	c.refreshing[k] = true
	c.refreshWG.Add(1)
	c.refreshMu.Unlock()
	if c.metrics != nil {
		c.metrics.DNSCacheRefresh.Inc()
	}
	go func() {
		defer c.refreshWG.Done()
		defer func() { c.refreshMu.Lock(); delete(c.refreshing, k); c.refreshMu.Unlock() }()
		if c.refreshSem != nil {
			c.refreshSem <- struct{}{}
			defer func() { <-c.refreshSem }()
		}
		started := time.Now()
		msg, err := resolve()
		if c.metrics != nil {
			c.metrics.DNSCacheRefreshDuration.Observe(time.Since(started).Seconds())
		}
		if err == nil && msg != nil && msg.Rcode == dns.RcodeSuccess && len(msg.Answer) > 0 {
			c.Set(q, msg)
			if c.metrics != nil {
				c.metrics.DNSCacheRefreshSuccess.Inc()
			}
			c.refreshMu.Lock()
			delete(c.refreshFailures, k)
			delete(c.refreshAfter, k)
			c.refreshMu.Unlock()
			return
		}
		if c.metrics != nil {
			c.metrics.DNSCacheRefreshFailed.Inc()
		}
		c.refreshMu.Lock()
		n := c.refreshFailures[k]
		if n < 20 {
			n++
		}
		c.refreshFailures[k] = n
		delay := c.retryMin * time.Duration(1<<min(n-1, 10))
		if delay > c.retryMax {
			delay = c.retryMax
		}
		delay = time.Duration(float64(delay) * (0.8 + rand.Float64()*0.4))
		c.refreshAfter[k] = time.Now().Add(delay)
		c.refreshMu.Unlock()
	}()
	return true
}

func (c *Cache) ShouldPrefetch(q dns.Question) bool {
	if c.prefetchThreshold <= 0 {
		return false
	}
	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.items[k]
	if e == nil || e.hits < 2 || e.originalTTL <= 0 {
		return false
	}
	left := time.Until(e.expiresAt)
	return left > 0 && left*100 <= e.originalTTL*time.Duration(c.prefetchThreshold)
}

func setMessageTTL(msg *dns.Msg, ttl uint32) {
	for _, set := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range set {
			if rr.Header() != nil && rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl = ttl
			}
		}
	}
}

func decrementMessageTTL(msg *dns.Msg, elapsed uint32) {
	for _, set := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range set {
			if h := rr.Header(); h != nil {
				if h.Rrtype == dns.TypeOPT {
					continue
				}
				if h.Ttl <= elapsed {
					h.Ttl = 0
				} else {
					h.Ttl -= elapsed
				}
			}
		}
	}
}

func (c *Cache) incHit() {
	if c.metrics != nil {
		c.metrics.IncCacheHits()
	}
}

func (c *Cache) incMiss() {
	if c.metrics != nil {
		c.metrics.IncCacheMisses()
	}
}

func (c *Cache) incEviction() {
	if c.metrics != nil {
		c.metrics.IncCacheEvictions()
	}
}

// reportEntries publishes the running entry count without holding a shard lock.
func (c *Cache) reportEntries() {
	if c.metrics != nil {
		c.metrics.SetCacheEntries(int(c.entries.Load()))
	}
}

func (c *Cache) extractTTL(msg *dns.Msg) time.Duration {
	minRR := uint32(0)
	found := false
	update := func(rr dns.RR) {
		h := rr.Header()
		if h == nil || h.Rrtype == dns.TypeOPT {
			return
		}
		if !found || h.Ttl < minRR {
			minRR = h.Ttl
			found = true
		}
	}

	for _, rr := range msg.Answer {
		update(rr)
	}
	for _, rr := range msg.Ns {
		update(rr)
	}
	for _, rr := range msg.Extra {
		update(rr)
	}

	if !found || minRR == 0 {
		return 0
	}
	ttl := time.Duration(minRR) * time.Second
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	return ttl
}

func (s *shard) evictOldest() {
	tail := s.ll.Back()
	if tail == nil {
		return
	}
	k, ok := tail.Value.(key)
	if !ok {
		s.ll.Remove(tail)
		return
	}
	if item, found := s.items[k]; found {
		s.remove(item)
		return
	}
	s.ll.Remove(tail)
}

func (s *shard) remove(e *entry) {
	delete(s.items, e.key)
	s.ll.Remove(e.element)
}

func (c *Cache) shardIndex(k key) int {
	// Inline FNV-1a avoids constructing a hash.Hash and temporary byte slices
	// on every lookup. Keep the qtype bytes in the same order as the old hash.
	h := uint64(14695981039346656037)
	for i := 0; i < len(k.fqdn); i++ {
		h ^= uint64(k.fqdn[i])
		h *= 1099511628211
	}
	h ^= uint64(byte(k.qtype >> 8))
	h *= 1099511628211
	h ^= uint64(byte(k.qtype))
	h *= 1099511628211
	h ^= uint64(byte(k.qclass >> 8))
	h *= 1099511628211
	h ^= uint64(byte(k.qclass))
	h *= 1099511628211
	return int(h % uint64(len(c.shards)))
}

func chooseShardCount(capacity int) int {
	if capacity < 1024 {
		return 1
	}
	if capacity < maxShards {
		return capacity
	}
	return maxShards
}

func shardCapacity(total, shards, idx int) int {
	base := total / shards
	rest := total % shards
	if idx < rest {
		base++
	}
	if base <= 0 {
		return 1
	}
	return base
}

func makeKey(q dns.Question) key {
	return key{
		fqdn:   strings.ToLower(dns.Fqdn(q.Name)),
		qtype:  q.Qtype,
		qclass: q.Qclass,
	}
}
