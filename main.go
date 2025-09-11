// main.go
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cornelk/hashmap"
	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
	"golang.org/x/sync/singleflight"
)

const (
	// basic server config
	ListenPort       = "5454"
	DefaultCacheTTL  = 300 * time.Second
	UDPDefaultSize   = 4096
	MaxUDPSize       = 65535
	WorkerMultiplier = 20

	// upstream / concurrency limits
	MaxUpstreamConns = 500

	// request queue size
	QueueSize = 100_000
)

// CacheItem хранит кэшированный dns.Msg
type CacheItem struct {
	Msg      *dns.Msg
	ExpireAt int64
	Auth     bool
}

var (
	// lock-free hashmap cache (generic API)
	cache = hashmap.New[uint64, *CacheItem]()

	// pools
	requestPool = sync.Pool{New: func() any { return &Request{} }}
	resolverPool = sync.Pool{New: func() any { return resolver.NewResolver() }}

	// upstream concurrency control
	upstreamSem = make(chan struct{}, MaxUpstreamConns)

	// group for in-flight dedupe
	inflight singleflight.Group

	// worker sync
	workerWG sync.WaitGroup

	// simple stats
	stats = struct {
		hits    uint64
		misses  uint64
		queries uint64
	}{}
)

// Request wrapper
type Request struct {
	w dns.ResponseWriter
	r *dns.Msg
}

// upstreamResult returned via singleflight
type upstreamResult struct {
	Msg  *dns.Msg
	Auth bool
	TTL  uint32
}

var ErrNoUpstreamSlot = errors.New("no upstream slot available")

// fnv64aLower — FNV-1a hash with on-the-fly ASCII lowercasing (no allocs)
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

func cacheGet(key uint64) *CacheItem {
	item, ok := cache.Get(key)
	if !ok {
		return nil
	}
	if time.Now().UnixNano() > item.ExpireAt {
		cache.Del(key)
		return nil
	}
	return item
}

func cacheSet(key uint64, msg *dns.Msg, auth bool, ttl uint32) {
	// clone msg to avoid data races if upstream reuse same struct
	item := &CacheItem{
		Msg:      msg.Copy(),
		ExpireAt: time.Now().Add(time.Duration(ttl) * time.Second).UnixNano(),
		Auth:     auth,
	}
	cache.Set(key, item)
}

func main() {
	// tune GOMAXPROCS
	_ = runtime.GOMAXPROCS(runtime.GOMAXPROCS(0))
	workers := runtime.GOMAXPROCS(0) * WorkerMultiplier
	requestQueue := make(chan *Request, QueueSize)

	// signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// start workers
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go worker(requestQueue)
	}

	// setup DNS servers (UDP + TCP)
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

	// start servers
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

	log.Printf("Workers: %d, QueueSize: %d, UpstreamLimit: %d", workers, QueueSize, MaxUpstreamConns)

	<-sig
	log.Println("Shutting down...")

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()

	close(requestQueue)
	workerWG.Wait()

	log.Println("Shutdown complete")
}

func enqueue(queue chan *Request, w dns.ResponseWriter, r *dns.Msg) {
	req := requestPool.Get().(*Request)
	req.w = w
	req.r = r
	select {
	case queue <- req:
	default:
		// queue full: respond REFUSED
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

	// validate
	if len(r.Question) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}

	q := r.Question[0]
	key := fnv64aLower(q.Name) ^ (uint64(q.Qtype) << 32)

	// fast cache hit
	if item := cacheGet(key); item != nil {
		atomic.AddUint64(&stats.hits, 1)

		reply := item.Msg.Copy()
		reply.Id = r.Id
		reply.Response = true
		if item.Auth {
			reply.AuthenticatedData = true
		}

		// truncate for UDP if needed
		isTCP := false
		if addr := w.RemoteAddr(); addr != nil && addr.Network() == "tcp" {
			isTCP = true
		}
		udpSize := uint16(UDPDefaultSize)
		if isTCP {
			udpSize = MaxUDPSize
		}
		if !isTCP && reply.Len() > int(udpSize) {
			reply.Truncate(int(udpSize))
		}

		if err := w.WriteMsg(reply); err != nil {
			log.Printf("WriteMsg (cache hit) error: %v", err)
		}
		return
	}
	atomic.AddUint64(&stats.misses, 1)

	// singleflight key (string)
	sfKey := strconv.FormatUint(key, 10)

	// Use singleflight to ensure only one upstream fetch for this key at a time.
	ch := inflight.DoChan(sfKey, func() (interface{}, error) {
		// acquire upstream slot (non-blocking)
		select {
		case upstreamSem <- struct{}{}:
			// acquired
		default:
			// no slot available
			return nil, ErrNoUpstreamSlot
		}
		start := time.Now()
		defer func() { <-upstreamSem }()

		// resolver
		res := resolverPool.Get().(*resolver.Resolver)
		defer resolverPool.Put(res)

		// prepare upstream query
		msg := new(dns.Msg)
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

		// perform exchange with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result := res.Exchange(ctx, msg)
		cancel()

		lat := time.Since(start)
		log.Printf("upstream latency for %s (%s): %v (err=%v)", q.Name, dns.TypeToString[q.Qtype], lat, result.Err)

		if result.Err != nil || result.Msg == nil {
			return nil, result.Err
		}

		isAuth := result.Auth == 1
		if isAuth {
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
		if isAuth && ttl > 300 {
			ttl = 300
		}

		// cache (cacheSet clones Msg)
		cacheSet(key, result.Msg, isAuth, ttl)

		// return upstreamResult (we return pointer to result.Msg; callers will copy)
		return &upstreamResult{Msg: result.Msg, Auth: isAuth, TTL: ttl}, nil
	})

	// wait for result
	resCh := <-ch
	if resCh.Err != nil {
		// upstream failed
		log.Printf("singleflight upstream error for %s: %v", q.Name, resCh.Err)
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	ur := resCh.Val.(*upstreamResult)

	// reply using cached copy
	reply := ur.Msg.Copy()
	reply.Id = r.Id
	reply.Response = true
	if ur.Auth {
		reply.AuthenticatedData = true
	}

	isTCP := false
	if addr := w.RemoteAddr(); addr != nil && addr.Network() == "tcp" {
		isTCP = true
	}
	udpSize := uint16(UDPDefaultSize)
	if isTCP {
		udpSize = MaxUDPSize
	}
	if !isTCP && reply.Len() > int(udpSize) {
		reply.Truncate(int(udpSize))
	}

	if err := w.WriteMsg(reply); err != nil {
		log.Printf("WriteMsg (final) error: %v", err)
	}
}
