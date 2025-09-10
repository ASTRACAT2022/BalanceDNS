// optimized_resolver.go
package main

import (
	"context"
	"log"
	"net"
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
	ShardCount        = 256 // power of two recommended
	DefaultUpstreamTO = 5 * time.Second
	UDPDefaultSize    = 4096
	MaxUDPSize        = 65535
	WorkerMultiplier  = 50 // workers = GOMAXPROCS * multiplier
	MaxUpstreamConns  = 500 // protect apis/roots from overload
)

// CacheItem хранит копию dns.Msg и метаданные
type CacheItem struct {
	Msg      *dns.Msg
	ExpireAt int64 // unix nano
	Auth     bool
}

// shard for concurrent cache
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

func (c *ShardedCache) shardFor(key string) *cacheShard {
	// simple xor-based hash
	h := fnv32a(key)
	return c.shards[int(h)&(ShardCount-1)]
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

func (c *ShardedCache) Get(key string) *dns.Msg {
	sh := c.shardFor(key)
	sh.RLock()
	item, ok := sh.m[key]
	if !ok {
		sh.RUnlock()
		return nil
	}
	// check expiration
	if atomic.LoadInt64(&item.ExpireAt) < time.Now().UnixNano() {
		sh.RUnlock()
		// Lazy delete
		sh.Lock()
		delete(sh.m, key)
		sh.Unlock()
		return nil
	}
	// return copy to avoid races
	msg := item.Msg.Copy()
	if item.Auth {
		msg.AuthenticatedData = true
	}
	sh.RUnlock()
	return msg
}

func (c *ShardedCache) Set(key string, msg *dns.Msg, auth bool, ttlSeconds uint32) {
	if msg == nil {
		return
	}
	sh := c.shardFor(key)
	sh.Lock()
	sh.m[key] = &CacheItem{
		Msg:      msg.Copy(),
		ExpireAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second).UnixNano(),
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
					if atomic.LoadInt64(&v.ExpireAt) < now {
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

// global state
var (
	cache        = NewShardedCache()
	resolverPool = sync.Pool{
		New: func() any {
			// configure resolver with reasonable defaults; the resolver package
			// will use system roots / defaults but you may configure custom transports here.
			return resolver.NewResolver()
		},
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
	runtime.GOMAXPROCS(runtime.GOMAXPROCS(0)) // keep default
	workers := runtime.GOMAXPROCS(0) * WorkerMultiplier
	queueSize := 100000 // large queue; backpressure handled by UDP handler

	requestQueue := make(chan *Request, queueSize)

	// start cleanup
	go cache.CleanupLoop(30*time.Second, stopCh)

	// start workers
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go worker(requestQueue)
	}

	// graceful shutdown
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

	// stop servers
	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()

	// stop workers
	close(requestQueue)
	workerWG.Wait()

	// stop cleanup
	close(stopCh)
	log.Println("Shutdown complete")
}

// Request wrapper
type Request struct {
	w dns.ResponseWriter
	r *dns.Msg
}

// enqueue with drop policy when full (returns RcodeRefused)
func enqueue(queue chan *Request, w dns.ResponseWriter, r *dns.Msg) {
	select {
	case queue <- &Request{w: w, r: r}:
	default:
		// queue full -> refuse
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
			continue
		}
		process(req.w, req.r)
	}
}

// process - core request handling (fast path for cache)
func process(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddUint64(&stats.queries, 1)

	// basic validation
	if len(r.Question) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}

	// build cache key
	q := r.Question[0]
	qname := strings.ToLower(q.Name)
	qtype := dns.TypeToString[q.Qtype]
	cacheKey := qname + ":" + qtype

	// check cache
	if msg := cache.Get(cacheKey); msg != nil {
		atomic.AddUint64(&stats.hits, 1)
		msg.Id = r.Id
		msg.Response = true
		// set AD flag already preserved on Get
		writeWithDeadline(w, msg)
		return
	}
	atomic.AddUint64(&stats.misses, 1)

	// get resolver from pool
	res := resolverPool.Get().(*resolver.Resolver)
	defer resolverPool.Put(res)

	// limit concurrent upstream queries with semaphore
	select {
	case upstreamSem <- struct{}{}:
		// got slot
	default:
		// upstream overloaded, respond SERVFAIL immediately
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}
	// release slot at end
	defer func() { <-upstreamSem }()

	// prepare message for upstream
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	isTCP := w.RemoteAddr().Network() == "tcp"

	udpSize := uint16(UDPDefaultSize)
	if isTCP {
		udpSize = MaxUDPSize
	}
	msg.SetEdns0(udpSize, true) // set DO bit for DNSSEC

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTO)
	defer cancel()

	result := res.Exchange(ctx, msg)
	if result.Err != nil || result.Msg == nil {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	// check auth (resolver returns Auth field as int; treat 1 = secure)
	isAuthenticated := result.Auth == 1
	if isAuthenticated {
		result.Msg.AuthenticatedData = true
	}

	// determine TTL to cache (min of answers or default)
	ttl := uint32(DefaultCacheTTL / time.Second)
	if len(result.Msg.Answer) > 0 {
		for _, rr := range result.Msg.Answer {
			h := rr.Header()
			if h.Ttl > 0 && h.Ttl < ttl {
				ttl = h.Ttl
			}
		}
	}
	// shorten TTL for DNSSEC-authenticated if desired (example)
	if isAuthenticated && ttl > 300 {
		ttl = 300
	}

	// store to cache
	cache.Set(cacheKey, result.Msg, isAuthenticated, ttl)

	// prepare reply
	result.Msg.Id = r.Id
	result.Msg.Response = true

	// UDP truncation handling (miekg/dns will do Truncate if Len>udp size)
	if !isTCP {
		// we already asked for EDNS0 size; but still ensure truncation
		if result.Msg.Len() > int(udpSize) {
			result.Msg.Truncate(int(udpSize))
		}
	}

	writeWithDeadline(w, result.Msg)
}

// writeWithDeadline sets a short write deadline to avoid slow clients stalling writers
func writeWithDeadline(w dns.ResponseWriter, msg *dns.Msg) {
	// set a small write deadline (helps under high QPS with slow clients)
	if conn, ok := w.RemoteAddr().(*net.TCPAddr); ok && conn != nil {
		// for TCP set deadline on underlying conn if possible
		// dns.ResponseWriter might implement SetWriteDeadline; try type assertion
		if sd, ok := w.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = sd.SetWriteDeadline(time.Now().Add(2 * time.Second))
		}
	}
	// UDP underlying writer doesn't implement SetWriteDeadline via iface reliably, so ignore

	_ = w.WriteMsg(msg)
}