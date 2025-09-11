// optimized_resolver_zero_copy.go
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

const (
	ListenPort        = "5454"
	DefaultCacheTTL   = 300 * time.Second
	ShardCount        = 256
	DefaultUpstreamTO = 5 * time.Second
	UDPDefaultSize    = 4096
	MaxUDPSize        = 65535
	WorkerMultiplier  = 50
	MaxUpstreamConns  = 500
)

// CacheItem now stores packed wire bytes to avoid repeated Pack/Copy.
type CacheItem struct {
	Wire     []byte // packed DNS wire format, header bytes included
	ExpireAt int64  // unix nano
	Auth     bool
}

type cacheShard struct {
	sync.RWMutex
	m map[string]*CacheItem
}

type ShardedCache struct {
	shards []*cacheShard
}

func NewShardedCache() *ShardedCache {
	s := make([]*cacheShard, ShardCount)
	for i := 0; i < ShardCount; i++ {
		s[i] = &cacheShard{m: make(map[string]*CacheItem)}
	}
	return &ShardedCache{shards: s}
}

func fnv32a(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	var h uint32 = offset32
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}

func (c *ShardedCache) shardFor(key string) *cacheShard {
	h := fnv32a(key)
	return c.shards[int(h)&(ShardCount-1)]
}

func (c *ShardedCache) Get(key string) *CacheItem {
	sh := c.shardFor(key)
	sh.RLock()
	item, ok := sh.m[key]
	if !ok {
		sh.RUnlock()
		return nil
	}
	// expiration check under RLock (Set writes under Lock)
	if item.ExpireAt < time.Now().UnixNano() {
		sh.RUnlock()
		// promote to write lock to delete stale entry
		sh.Lock()
		if v, ok2 := sh.m[key]; ok2 && v.ExpireAt < time.Now().UnixNano() {
			delete(sh.m, key)
		}
		sh.Unlock()
		return nil
	}
	sh.RUnlock()
	return item
}

// Set will pack msg to wire and store the wire bytes
func (c *ShardedCache) Set(key string, msg *dns.Msg, auth bool, ttlSeconds uint32) {
	if msg == nil {
		return
	}
	// Pack with large size (MaxUDPSize) to keep full message in cache.
	wire, err := msg.Pack()
	if err != nil {
		// packing failed, skip cache store
		return
	}
	exp := time.Now().Add(time.Duration(ttlSeconds) * time.Second).UnixNano()
	sh := c.shardFor(key)
	sh.Lock()
	// store a copy of wire to ensure immutability
	newWire := make([]byte, len(wire))
	copy(newWire, wire)
	sh.m[key] = &CacheItem{
		Wire:     newWire,
		ExpireAt: exp,
		Auth:     auth,
	}
	sh.Unlock()
}

func (c *ShardedCache) CleanupLoop(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			for _, sh := range c.shards {
				sh.Lock()
				for k, v := range sh.m {
					if v.ExpireAt < now {
						delete(sh.m, k)
					}
				}
				sh.Unlock()
			}
		case <-stop:
			return
		}
	}
}

var (
	cache = NewShardedCache()

	resolverPool = sync.Pool{
		New: func() any { return resolver.NewResolver() },
	}

	requestPool = sync.Pool{
		New: func() any { return &Request{} },
	}

	// small pool for temporary small buffers (not crucial, but helps)
	bufPool = sync.Pool{
		New: func() any { return make([]byte, 0, 512) },
	}

	upstreamSem = make(chan struct{}, MaxUpstreamConns)
	upstreamTO  = DefaultUpstreamTO

	workerWG sync.WaitGroup
	stopCh   = make(chan struct{})
	stats    = struct {
		hits    uint64
		misses  uint64
		queries uint64
	}{}
)

func main() {
	_ = runtime.GOMAXPROCS(runtime.GOMAXPROCS(0))
	workers := runtime.GOMAXPROCS(0) * WorkerMultiplier
	queueSize := 100000
	requestQueue := make(chan *Request, queueSize)

	go cache.CleanupLoop(30*time.Second, stopCh)

	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go worker(requestQueue)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	udpServer := &dns.Server{
		Addr:    ":" + ListenPort,
		Net:     "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { enqueue(requestQueue, w, r) }),
		UDPSize: UDPDefaultSize,
	}
	tcpServer := &dns.Server{
		Addr:    ":" + ListenPort,
		Net:     "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { enqueue(requestQueue, w, r) }),
	}

	go func() {
		log.Printf("Starting UDP server on :%s", ListenPort)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("UDP ListenAndServe: %v", err)
		}
	}()
	go func() {
		log.Printf("Starting TCP server on :%s", ListenPort)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("TCP ListenAndServe: %v", err)
		}
	}()

	log.Printf("Workers: %d, QueueSize: %d, UpstreamLimit: %d", workers, queueSize, MaxUpstreamConns)

	<-sig
	log.Println("Shutting down...")

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()

	close(requestQueue)
	workerWG.Wait()

	close(stopCh)
	log.Println("Shutdown complete")
}

type Request struct {
	w dns.ResponseWriter
	r *dns.Msg
}

func enqueue(queue chan *Request, w dns.ResponseWriter, r *dns.Msg) {
	req := requestPool.Get().(*Request)
	req.w = w
	req.r = r
	select {
	case queue <- req:
	default:
		requestPool.Put(req)
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(reply)
	}
}

func worker(queue chan *Request) {
	defer workerWG.Done()
	for req := range queue {
		if req == nil || req.r == nil {
			if req != nil {
				req.w = nil
				req.r = nil
				requestPool.Put(req)
			}
			continue
		}
		process(req.w, req.r)
		req.w = nil
		req.r = nil
		requestPool.Put(req)
	}
}

func process(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddUint64(&stats.queries, 1)

	if len(r.Question) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)
	qtype := dns.TypeToString[q.Qtype]
	cacheKey := qname + ":" + qtype

	// fast cached wire path
	if item := cache.Get(cacheKey); item != nil {
		atomic.AddUint64(&stats.hits, 1)
		// item.Wire is immutable slice owned by cache
		// We need to set request ID. Instead of copying full slice, we write:
		// 1) ID bytes (2)
		// 2) rest of wire (from byte index 2)
		// This avoids allocating full copy to change first two bytes.
		id := r.Id
		idb := [2]byte{byte(id >> 8), byte(id & 0xff)}

		// check if we need to truncate for UDP
		isTCP := w.RemoteAddr().Network() == "tcp"
		udpSize := uint16(UDPDefaultSize)
		if isTCP {
			udpSize = MaxUDPSize
		}
		// fast path: if len fits UDP size or connection is TCP -> just write as two writes
		if isTCP || len(item.Wire) <= int(udpSize) {
			// Attempt to write without extra copies:
			// Some dns.ResponseWriters may buffer/expect WriteMsg, but ResponseWriter implements io.Writer in miekg/dns.
			// We ignore write errors here (like previous code).
			_, _ = w.Write(idb[:])
			_, _ = w.Write(item.Wire[2:])
			return
		}
		// else: wire too large for UDP -> parse and truncate (rare)
		var parsed dns.Msg
		if err := parsed.Unpack(item.Wire); err != nil {
			// fallback: send SERVFAIL
			reply := new(dns.Msg)
			reply.SetReply(r)
			reply.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(reply)
			return
		}
		parsed.Id = r.Id
		parsed.Response = true
		parsed.Truncate(int(udpSize))
		// set AD if cached as auth
		if item.Auth {
			parsed.AuthenticatedData = true
		}
		_ = w.WriteMsg(&parsed)
		return
	}
	atomic.AddUint64(&stats.misses, 1)

	// get resolver
	res := resolverPool.Get().(*resolver.Resolver)

	// upstream semaphore
	select {
	case upstreamSem <- struct{}{}:
	default:
		resolverPool.Put(res)
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	// prepare upstream query
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	isTCP := w.RemoteAddr().Network() == "tcp"
	udpSize := uint16(UDPDefaultSize)
	if isTCP {
		udpSize = MaxUDPSize
	}
	msg.SetEdns0(udpSize, true)

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTO)
	result := res.Exchange(ctx, msg)
	cancel()
	// return resolver asap
	resolverPool.Put(res)
	<-upstreamSem

	if result.Err != nil || result.Msg == nil {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	isAuthenticated := result.Auth == 1
	if isAuthenticated {
		result.Msg.AuthenticatedData = true
	}

	// determine TTL
	ttl := uint32(DefaultCacheTTL / time.Second)
	if len(result.Msg.Answer) > 0 {
		for _, rr := range result.Msg.Answer {
			h := rr.Header()
			if h.Ttl > 0 && h.Ttl < ttl {
				ttl = h.Ttl
			}
		}
	}
	if isAuthenticated && ttl > 300 {
		ttl = 300
	}

	// store in cache as packed wire
	cache.Set(cacheKey, result.Msg, isAuthenticated, ttl)

	// send reply (normal path)
	result.Msg.Id = r.Id
	result.Msg.Response = true
	if !isTCP {
		if result.Msg.Len() > int(udpSize) {
			result.Msg.Truncate(int(udpSize))
		}
	}
	_ = w.WriteMsg(result.Msg)
}
