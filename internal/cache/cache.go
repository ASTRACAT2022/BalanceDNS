package cache

import (
	"container/list"
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
	key       key
	message   *dns.Msg
	expiresAt time.Time
	element   *list.Element
}

type shard struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[key]*entry
}

type Cache struct {
	minTTL  time.Duration
	maxTTL  time.Duration
	shards  []shard
	metrics *metrics.Provider

	// entries is a running count of cached items, updated atomically on
	// insert/evict/expire. It is O(1) and avoids locking all shards from
	// within a shard-critical section (which would deadlock).
	entries atomic.Int64
}

func New(capacity int, minTTLSeconds, maxTTLSeconds uint32) *Cache {
	return NewWithMetrics(capacity, minTTLSeconds, maxTTLSeconds, nil)
}

func NewWithMetrics(capacity int, minTTLSeconds, maxTTLSeconds uint32, m *metrics.Provider) *Cache {
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
		minTTL:  time.Duration(minTTLSeconds) * time.Second,
		maxTTL:  normalizedMaxTTL(minTTLSeconds, maxTTLSeconds),
		shards:  shards,
		metrics: m,
	}
}

func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]

	s.mu.Lock()
	item, ok := s.items[k]
	if !ok {
		s.mu.Unlock()
		c.incMiss()
		return nil, false
	}
	now := time.Now()
	if !now.Before(item.expiresAt) {
		s.remove(item)
		c.entries.Add(-1)
		s.mu.Unlock()
		c.incEviction()
		c.reportEntries()
		c.incMiss()
		return nil, false
	}

	s.ll.MoveToFront(item.element)
	message := item.message
	remaining := item.expiresAt.Sub(now)
	s.mu.Unlock()

	c.incHit()
	// Entries are immutable after insertion; replacement only swaps the
	// pointer while holding the shard lock. It is therefore safe to copy this
	// snapshot outside the lock, greatly reducing reader contention.
	return responseWithRemainingTTL(message, remaining), true
}

// Set stores a defensive copy of response. DNS messages are mutable and the
// resolver continues to use the original message after this call.
func (c *Cache) Set(q dns.Question, response *dns.Msg) {
	// A truncated UDP response is incomplete; caching it would make every
	// later client receive the same incomplete answer instead of retrying TCP.
	if response == nil || response.Truncated {
		return
	}

	ttl := c.extractTTL(response)
	if ttl <= 0 {
		return
	}

	// Copy before acquiring the shard lock. This is the expensive part of a
	// write and does not need synchronization with the cache itself.
	message := response.Copy()
	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]
	expiresAt := time.Now().Add(ttl)

	s.mu.Lock()
	if current, ok := s.items[k]; ok {
		current.message = message
		current.expiresAt = expiresAt
		s.ll.MoveToFront(current.element)
		s.mu.Unlock()
		return
	}

	elem := s.ll.PushFront(k)
	s.items[k] = &entry{
		key:       k,
		message:   message,
		expiresAt: expiresAt,
		element:   elem,
	}

	evicted := false
	if len(s.items) > s.cap {
		s.evictOldest()
		c.entries.Add(-1)
		evicted = true
	}
	c.entries.Add(1)
	s.mu.Unlock()
	if evicted {
		c.incEviction()
	}
	c.reportEntries()
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

// reportEntries publishes the running entry count. It is O(1) and safe to
// call from within a shard-critical section.
func (c *Cache) reportEntries() {
	if c.metrics != nil {
		c.metrics.SetCacheEntries(int(c.entries.Load()))
	}
}

func (c *Cache) extractTTL(msg *dns.Msg) time.Duration {
	minRR := uint32(0)
	update := func(rr dns.RR) {
		h := rr.Header()
		if h == nil || h.Ttl == 0 {
			return
		}
		if minRR == 0 || h.Ttl < minRR {
			minRR = h.Ttl
		}
	}

	for _, rr := range msg.Answer {
		update(rr)
	}
	for _, rr := range msg.Ns {
		update(rr)
	}
	for _, rr := range msg.Extra {
		// OPT's TTL field contains EDNS extended flags, not a DNS TTL.
		if h := rr.Header(); h != nil && h.Rrtype == dns.TypeOPT {
			continue
		}
		update(rr)
	}

	// Do not invent a TTL for an empty or explicitly zero-TTL response.
	// Such data is not cacheable according to DNS semantics.
	if minRR == 0 {
		return 0
	}
	ttl := time.Duration(minRR) * time.Second
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	return ttl
}

func normalizedMaxTTL(minTTLSeconds, maxTTLSeconds uint32) time.Duration {
	maxTTL := time.Duration(maxTTLSeconds) * time.Second
	minTTL := time.Duration(minTTLSeconds) * time.Second
	if maxTTL == 0 || maxTTL < minTTL {
		return minTTL
	}
	return maxTTL
}

// responseWithRemainingTTL returns a copy whose TTLs reflect the time that
// remains in the cache. Returning the original TTL would make downstream DNS
// clients cache stale data beyond the cache entry's expiry.
func responseWithRemainingTTL(message *dns.Msg, remaining time.Duration) *dns.Msg {
	copy := message.Copy()
	seconds := uint32(remaining / time.Second)
	adjust := func(records []dns.RR) {
		for _, rr := range records {
			if h := rr.Header(); h != nil && h.Ttl > seconds {
				h.Ttl = seconds
			}
		}
	}
	adjust(copy.Answer)
	adjust(copy.Ns)
	adjust(copy.Extra)
	return copy
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
	// Inline FNV-1a avoids allocating a hash.Hash object for every lookup.
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(k.fqdn); i++ {
		h ^= uint64(k.fqdn[i])
		h *= prime64
	}
	for _, b := range [...]byte{byte(k.qtype >> 8), byte(k.qtype), byte(k.qclass >> 8), byte(k.qclass)} {
		h ^= uint64(b)
		h *= prime64
	}
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
