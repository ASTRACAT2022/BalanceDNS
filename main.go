// iterative_resolver.go
package main

import (
	"context"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	ListenPort       = "5454"
	DefaultCacheTTL  = 300 * time.Second
	ShardCount       = 256
	WorkerMultiplier = 50
	MaxUpstreamConns = 500

	PrefetchInterval   = 30 * time.Second
	PrefetchThreshold  = 0.1 // обновляем если TTL <10% от исходного
)

type CacheItem struct {
	Msg         *dns.Msg
	ExpireAt    int64
	Auth        bool
	OriginalTTL uint32
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

func (c *ShardedCache) Get(key string) *dns.Msg {
	sh := c.shardFor(key)
	sh.RLock()
	item, ok := sh.m[key]
	if !ok {
		sh.RUnlock()
		return nil
	}
	if time.Now().UnixNano() > item.ExpireAt {
		sh.RUnlock()
		sh.Lock()
		delete(sh.m, key)
		sh.Unlock()
		return nil
	}
	msg := item.Msg.Copy()
	if item.Auth {
		msg.AuthenticatedData = true
	}
	sh.RUnlock()
	return msg
}

func (c *ShardedCache) Set(key string, msg *dns.Msg, auth bool, ttl uint32) {
	if msg == nil {
		return
	}
	sh := c.shardFor(key)
	sh.Lock()
	sh.m[key] = &CacheItem{
		Msg:         msg.Copy(),
		ExpireAt:    time.Now().Add(time.Duration(ttl) * time.Second).UnixNano(),
		Auth:        auth,
		OriginalTTL: ttl,
	}
	sh.Unlock()
}

func (c *ShardedCache) CleanupLoop(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
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

func (c *ShardedCache) PrefetchLoop(stop <-chan struct{}) {
	t := time.NewTicker(PrefetchInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			now := time.Now().UnixNano()
			for _, sh := range c.shards {
				sh.RLock()
				for k, v := range sh.m {
					remaining := float64(v.ExpireAt-now) / 1e9
					if remaining <= PrefetchThreshold*float64(v.OriginalTTL) {
						// запускаем фоновое обновление
						go prefetchRecord(k, v)
					}
				}
				sh.RUnlock()
			}
		case <-stop:
			return
		}
	}
}

var (
	cache       = NewShardedCache()
	upstreamSem = make(chan struct{}, MaxUpstreamConns)
	workerWG    sync.WaitGroup
	stopCh      = make(chan struct{})
)

type Request struct {
	w dns.ResponseWriter
	r *dns.Msg
}

var rootServers = []string{
	"a.root-servers.net:53",
	"b.root-servers.net:53",
	"c.root-servers.net:53",
	"d.root-servers.net:53",
	"e.root-servers.net:53",
	"f.root-servers.net:53",
	"g.root-servers.net:53",
	"h.root-servers.net:53",
	"i.root-servers.net:53",
	"j.root-servers.net:53",
	"k.root-servers.net:53",
	"l.root-servers.net:53",
	"m.root-servers.net:53",
}

func main() {
	workers := WorkerMultiplier
	queue := make(chan *Request, 10000)

	go cache.CleanupLoop(30*time.Second, stopCh)
	go cache.PrefetchLoop(stopCh)

	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go worker(queue)
	}

	udpServer := &dns.Server{
		Addr:    ":" + ListenPort,
		Net:     "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { enqueue(queue, w, r) }),
		UDPSize: 4096,
	}
	tcpServer := &dns.Server{
		Addr:    ":" + ListenPort,
		Net:     "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { enqueue(queue, w, r) }),
	}

	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("DNS Recursive Resolver with Prefetch running on port", ListenPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
	close(queue)
	workerWG.Wait()
	close(stopCh)
}

func enqueue(queue chan *Request, w dns.ResponseWriter, r *dns.Msg) {
	select {
	case queue <- &Request{w, r}:
	default:
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(reply)
	}
}

func worker(queue chan *Request) {
	defer workerWG.Done()
	for req := range queue {
		process(req.w, req.r)
	}
}

func process(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}

	q := r.Question[0]
	cacheKey := strings.ToLower(q.Name) + ":" + dns.TypeToString[q.Qtype]
	if msg := cache.Get(cacheKey); msg != nil {
		msg.Id = r.Id
		_ = w.WriteMsg(msg)
		return
	}

	select {
	case upstreamSem <- struct{}{}:
		defer func() { <-upstreamSem }()
	default:
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, ttl := iterativeResolve(ctx, q.Name, q.Qtype)
	if resp == nil {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	resp.Id = r.Id
	resp.Response = true
	cache.Set(cacheKey, resp, false, ttl)

	_ = w.WriteMsg(resp)
}

func iterativeResolve(ctx context.Context, qname string, qtype uint16) (*dns.Msg, uint32) {
	servers := make([]string, len(rootServers))
	copy(servers, rootServers)

	for {
		server := servers[rand.Intn(len(servers))]

		m := new(dns.Msg)
		m.SetQuestion(qname, qtype)
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetDo()
		o.SetUDPSize(4096)
		o.Option = append(o.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 128)})
		m.Extra = append(m.Extra, o)

		// Исправлено: dns.ExchangeContext возвращает 2 значения
		in, err := dns.ExchangeContext(ctx, m, server)
		if err != nil {
			continue
		}
		if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
			continue
		}

		if in.Rcode == dns.RcodeNameError || (len(in.Answer) == 0 && len(in.Ns) > 0) {
			return in, 60
		}

		if len(in.Answer) > 0 {
			ttl := uint32(DefaultCacheTTL.Seconds())
			for _, rr := range in.Answer {
				if rr.Header().Ttl < ttl {
					ttl = rr.Header().Ttl
				}
			}
			return in, ttl
		}

		var ns []string
		for _, rr := range in.Ns {
			if rr.Header().Rrtype == dns.TypeNS {
				ns = append(ns, rr.(*dns.NS).Ns)
			}
		}
		var addrs []string
		for _, rr := range in.Extra {
			switch a := rr.(type) {
			case *dns.A:
				addrs = append(addrs, net.JoinHostPort(a.A.String(), "53"))
			case *dns.AAAA:
				addrs = append(addrs, net.JoinHostPort(a.AAAA.String(), "53"))
			}
		}
		if len(addrs) > 0 {
			servers = addrs
		} else if len(ns) > 0 {
			servers = make([]string, 0, len(ns))
			for _, n := range ns {
				servers = append(servers, n+":53")
			}
		} else {
			return in, 60
		}
	}
}

// Prefetch обновляет запись в кэше до истечения TTL
func prefetchRecord(key string, item *CacheItem) {
	select {
	case upstreamSem <- struct{}{}:
		defer func() { <-upstreamSem }()
	default:
		return
	}

	qParts := strings.SplitN(key, ":", 2)
	if len(qParts) != 2 {
		return
	}
	qname, qtypeStr := qParts[0], qParts[1]
	qtype, ok := dns.StringToType[qtypeStr]
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, ttl := iterativeResolve(ctx, qname, qtype)
	if resp != nil {
		cache.Set(key, resp, false, ttl)
	}
}