// main.go — безопасный вариант: только WriteMsg, логирование ошибок
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
	ListenPort           = "5454"
	DefaultCacheTTL      = 300 * time.Second
	ShardCount           = 256
	DefaultUpstreamTO    = 5 * time.Second
	RootUpstreamTO       = 10 * time.Second
	UDPDefaultSize       = 4096
	MaxUDPSize           = 65535
	WorkerMultiplier     = 20
	MaxUpstreamConns     = 1000
	RootMaxUpstreamConns = 2000
	QueueSizeDefault     = 100000
)

type CacheItem struct {
	Wire     []byte
	ExpireAt int64
	Auth     bool
}

type cacheShard struct {
	sync.RWMutex
	m map[uint64]*CacheItem
}

type ShardedCache struct {
	shards []*cacheShard
}

func NewShardedCache() *ShardedCache {
	s := make([]*cacheShard, ShardCount)
	for i := 0; i < ShardCount; i++ {
		s[i] = &cacheShard{m: make(map[uint64]*CacheItem)}
	}
	return &ShardedCache{shards: s}
}

func fnv64aLower(s string) uint64 {
	const (
		offset64 = uint64(14695981039346656037)
		prime64  = uint64(1099511628211)
	)
	var h uint64 = offset64
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		h ^= uint64(b)
		h *= prime64
	}
	return h
}

func (c *ShardedCache) shardForHash(h uint64) *cacheShard {
	return c.shards[int(h)&(ShardCount-1)]
}

func (c *ShardedCache) GetHashKey(hash uint64) *CacheItem {
	sh := c.shardForHash(hash)
	sh.RLock()
	item, ok := sh.m[hash]
	if !ok {
		sh.RUnlock()
		return nil
	}
	now := time.Now().UnixNano()
	if item.ExpireAt < now {
		sh.RUnlock()
		sh.Lock()
		if v, ok2 := sh.m[hash]; ok2 && v.ExpireAt < now {
			delete(sh.m, hash)
		}
		sh.Unlock()
		return nil
	}
	sh.RUnlock()
	return item
}

func (c *ShardedCache) SetHashKey(hash uint64, wire []byte, auth bool, ttlSeconds uint32) {
	if wire == nil {
		return
	}
	exp := time.Now().Add(time.Duration(ttlSeconds) * time.Second).UnixNano()
	sh := c.shardForHash(hash)
	sh.Lock()
	sh.m[hash] = &CacheItem{
		Wire:     wire,
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

	msgPool = sync.Pool{
		New: func() any { return new(dns.Msg) },
	}

	upstreamSem     = make(chan struct{}, MaxUpstreamConns)
	rootUpstreamSem = make(chan struct{}, RootMaxUpstreamConns)

	upstreamTO = DefaultUpstreamTO

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
	queueSize := QueueSizeDefault
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

	log.Printf("Workers: %d, QueueSize: %d, UpstreamLimit: %d, RootUpstreamLimit: %d", workers, queueSize, MaxUpstreamConns, RootMaxUpstreamConns)

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

func isRootQuestion(q dns.Question) bool {
	name := strings.TrimSpace(q.Name)
	return name == "." || name == ""
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
	nameHash := fnv64aLower(q.Name)
	keyHash := nameHash ^ (uint64(q.Qtype) << 32)

	// cache hit: unpack -> set Id -> WriteMsg (no raw writes)
	if item := cache.GetHashKey(keyHash); item != nil {
		atomic.AddUint64(&stats.hits, 1)
		var parsed dns.Msg
		if err := parsed.Unpack(item.Wire); err != nil {
			log.Printf("cache unpack error: %v", err)
			reply := new(dns.Msg)
			reply.SetReply(r)
			reply.SetRcode(r, dns.RcodeServerFailure)
			_ = w.WriteMsg(reply)
			return
		}
		parsed.Id = r.Id
		parsed.Response = true
		if item.Auth {
			parsed.AuthenticatedData = true
		}

		isTCP := false
		if addr := w.RemoteAddr(); addr != nil && addr.Network() == "tcp" {
			isTCP = true
		}
		udpSize := uint16(UDPDefaultSize)
		if isTCP {
			udpSize = MaxUDPSize
		}
		if !isTCP && parsed.Len() > int(udpSize) {
			parsed.Truncate(int(udpSize))
		}
		if err := w.WriteMsg(&parsed); err != nil {
			log.Printf("WriteMsg (cache hit) error: %v", err)
		}
		return
	}
	atomic.AddUint64(&stats.misses, 1)

	// choose sem & timeout
	useRootSem := isRootQuestion(q)
	var sem chan struct{}
	var timeout time.Duration
	if useRootSem {
		sem = rootUpstreamSem
		timeout = RootUpstreamTO
	} else {
		sem = upstreamSem
		timeout = upstreamTO
	}

	select {
	case sem <- struct{}{}:
	default:
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}
	defer func() { <-sem }()

	res := resolverPool.Get().(*resolver.Resolver)
	defer resolverPool.Put(res)

	msg := msgPool.Get().(*dns.Msg)
	*msg = dns.Msg{}
	msg.SetQuestion(q.Name, q.Qtype)
	isTCP := false
	if addr := w.RemoteAddr(); addr != nil && addr.Network() == "tcp" {
		isTCP = true
	}
	udpSize := uint16(UDPDefaultSize)
	if isTCP {
		udpSize = MaxUDPSize
	}
	msg.SetEdns0(udpSize, true)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	result := res.Exchange(ctx, msg)
	cancel()
	msgPool.Put(msg)

	if result.Err != nil || result.Msg == nil {
		log.Printf("upstream error: %v", result.Err)
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

	wire, err := result.Msg.Pack()
	if err == nil {
		cache.SetHashKey(keyHash, wire, isAuthenticated, ttl)
	} else {
		log.Printf("pack error: %v", err)
	}

	result.Msg.Id = r.Id
	result.Msg.Response = true
	if !isTCP {
		if result.Msg.Len() > int(udpSize) {
			result.Msg.Truncate(int(udpSize))
		}
	}
	if err := w.WriteMsg(result.Msg); err != nil {
		log.Printf("WriteMsg (upstream reply) error: %v", err)
	}
}
