// main.go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	"golang.org/x/sync/singleflight"
)

const (
	// Default constants (can be overridden by flags)
	DefaultListenPort       = "5454"
	DefaultCacheTTL         = 300 * time.Second
	DefaultUDPSize          = 4096
	DefaultMaxUDPSize       = 65535
	DefaultWorkerMultiplier = 5

	DefaultMaxConcurrentRecursions = 500
	DefaultMaxRecursionDepth       = 15
	DefaultQueryTimeout            = 4 * time.Second
	DefaultParallelNameServers     = 3

	DefaultQueueSize = 100_000

	// Cache entry types
	CacheTypeFinalResponse = iota
	CacheTypeNSAddr
	CacheTypeNS
	// Note: Caching DNSKEY/DS is complex and requires proper validation logic
	// which is not fully implemented here. We cache them for structure,
	// but the validation part is simplified (trust upstream AD flag).
	// CacheTypeDNSKEY
	// CacheTypeDS

	// Log levels
	LogLevelError = iota
	LogLevelInfo
	LogLevelDebug
)

// LogLevel holds the current logging level
var LogLevel = LogLevelInfo

// Log functions with level checking
func logError(format string, v ...interface{}) {
	if LogLevel >= LogLevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}

func logInfo(format string, v ...interface{}) {
	if LogLevel >= LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

func logDebug(format string, v ...interface{}) {
	if LogLevel >= LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// --- Config holds parsed command-line flags ---
type Config struct {
	ListenPort       string
	WorkerMultiplier int
	LogLevel         int
	QueueSize        int
}

// CacheItem хранит кэшированный элемент
type CacheItem struct {
	Data     interface{}
	ExpireAt int64
	Type     int
}

// ServerStats holds various server statistics
type ServerStats struct {
	TotalQueries     uint64
	TotalCacheHits   uint64
	TotalCacheMisses uint64
}

func (s *ServerStats) Snapshot() (queries, hits, misses uint64) {
	queries = atomic.LoadUint64(&s.TotalQueries)
	hits = atomic.LoadUint64(&s.TotalCacheHits)
	misses = atomic.LoadUint64(&s.TotalCacheMisses)
	return
}

func (s *ServerStats) PrintPeriodically(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			q, h, m := s.Snapshot()
			hitRate := 0.0
			if q > 0 {
				hitRate = float64(h) / float64(q) * 100
			}
			logInfo("Stats - Queries: %d, Hits: %d, Misses: %d, Hit Rate: %.2f%%", q, h, m, hitRate)
		case <-ctx.Done():
			logInfo("Stats printer stopped.")
			return
		}
	}
}

var (
	// Global config
	config *Config

	// lock-free hashmap cache (generic API)
	cache = hashmap.New[uint64, *CacheItem]()

	// pools
	requestPool = sync.Pool{New: func() any { return &Request{} }}

	// recursion concurrency control
	recursionSem = make(chan struct{}, DefaultMaxConcurrentRecursions)

	// group for in-flight dedupe
	inflight singleflight.Group

	// worker sync
	workerWG sync.WaitGroup

	// Server statistics
	stats = &ServerStats{}

	// Root hints (A records for simplicity)
	rootServers = []string{
		"198.41.0.4:53",   // a.root-servers.net
		"199.9.14.201:53", // b.root-servers.net
		"192.33.4.12:53",  // c.root-servers.net
		"199.7.91.13:53",  // d.root-servers.net
		"192.203.230.10:53", // e.root-servers.net
		"192.5.5.241:53",  // f.root-servers.net
		"192.112.36.4:53", // g.root-servers.net
		"198.97.190.53:53", // h.root-servers.net
		"192.36.148.17:53", // i.root-servers.net
		"192.58.128.30:53", // j.root-servers.net
		"193.0.14.129:53", // k.root-servers.net
		"199.7.83.42:53",  // l.root-servers.net
		"202.12.27.33:53", // m.root-servers.net
	}

	// DNS client for outgoing queries
	dnsClient *dns.Client
)

// Request wrapper
type Request struct {
	w dns.ResponseWriter
	r *dns.Msg
}

// upstreamResult returned via singleflight
type upstreamResult struct {
	Msg  *dns.Msg
	Auth bool // This will be the upstream AD flag
	TTL  uint32
}

var (
	ErrMaxRecursionDepth = errors.New("maximum recursion depth exceeded")
	ErrNoRecursionSlot   = errors.New("no recursion slot available")
	ErrQueryTimeout      = errors.New("query timeout")
	ErrResolveFailed     = errors.New("resolution failed")
	ErrNoNameservers     = errors.New("no nameservers found or resolved")
)

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

// --- Cache Helpers ---
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

func cacheGetEntry(key uint64, entryType int) *CacheItem {
	item := cacheGet(key)
	if item != nil && item.Type == entryType {
		return item
	}
	return nil
}

func cacheSetEntry(key uint64, data interface{}, entryType int, ttl uint32) {
	expireAt := time.Now().Add(time.Duration(ttl) * time.Second).UnixNano()
	if ttl > uint32(DefaultCacheTTL/time.Second) {
		expireAt = time.Now().Add(DefaultCacheTTL).UnixNano()
	}
	item := &CacheItem{
		Data:     data,
		ExpireAt: expireAt,
		Type:     entryType,
	}
	cache.Set(key, item)
}

func cacheGetNSAddrs(nsName string) []string {
	key := fnv64aLower(nsName)
	item := cacheGetEntry(key, CacheTypeNSAddr)
	if item != nil {
		if addrs, ok := item.Data.([]string); ok {
			return addrs
		}
	}
	return nil
}

func cacheSetNSAddrs(nsName string, addrs []string, ttl uint32) {
	key := fnv64aLower(nsName)
	cacheSetEntry(key, addrs, CacheTypeNSAddr, ttl)
}

func cacheGetNS(domain string) []string {
	key := fnv64aLower(domain) ^ (uint64(dns.TypeNS) << 32)
	item := cacheGetEntry(key, CacheTypeNS)
	if item != nil {
		if nss, ok := item.Data.([]string); ok {
			return nss
		}
	}
	return nil
}

func cacheSetNS(domain string, nss []string, ttl uint32) {
	key := fnv64aLower(domain) ^ (uint64(dns.TypeNS) << 32)
	cacheSetEntry(key, nss, CacheTypeNS, ttl)
}

// --- End Cache Helpers ---

func main() {
	// Parse command-line flags
	flagPort := flag.String("port", DefaultListenPort, "DNS server listen port")
	flagWorkers := flag.Int("workers", DefaultWorkerMultiplier, "Worker multiplier (GOMAXPROCS * workers)")
	flagLogLevel := flag.String("loglevel", "info", "Log level (error, info, debug)")
	flagQueueSize := flag.Int("queuesize", DefaultQueueSize, "Size of the request queue")

	flag.Parse()

	// Map string log level to int
	logLevel := LogLevelInfo
	switch *flagLogLevel {
	case "error":
		logLevel = LogLevelError
	case "info":
		logLevel = LogLevelInfo
	case "debug":
		logLevel = LogLevelDebug
	default:
		log.Printf("Unknown log level '%s', defaulting to 'info'", *flagLogLevel)
	}
	LogLevel = logLevel

	// Store config
	config = &Config{
		ListenPort:       *flagPort,
		WorkerMultiplier: *flagWorkers,
		LogLevel:         logLevel,
		QueueSize:        *flagQueueSize,
	}

	// tune GOMAXPROCS
	maxProcs := runtime.GOMAXPROCS(0)
	workers := maxProcs * config.WorkerMultiplier
	requestQueue := make(chan *Request, config.QueueSize)

	logInfo("Starting DNS server with config: Port=%s, Workers=%d (GOMAXPROCS=%d * Multiplier=%d), QueueSize=%d, LogLevel=%s",
		config.ListenPort, workers, maxProcs, config.WorkerMultiplier, config.QueueSize, *flagLogLevel)

	// Инициализируем DNS клиент
	dnsClient = &dns.Client{
		Net: "udp",
	}

	// signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Context for graceful shutdown and stats
	mainCtx, cancelMain := context.WithCancel(context.Background())
	defer cancelMain()

	// Start periodic stats printing
	go stats.PrintPeriodically(mainCtx, 10*time.Second)

	// start workers
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go worker(requestQueue)
	}

	// setup DNS servers (UDP + TCP)
	udpServer := &dns.Server{
		Addr:    ":" + config.ListenPort,
		Net:     "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { enqueue(requestQueue, w, r) }),
		UDPSize: DefaultUDPSize,
	}
	tcpServer := &dns.Server{
		Addr:    ":" + config.ListenPort,
		Net:     "tcp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { enqueue(requestQueue, w, r) }),
	}

	// start servers
	go func() {
		logInfo("Starting UDP server on :%s", config.ListenPort)
		if err := udpServer.ListenAndServe(); err != nil {
			logError("UDP ListenAndServe: %v", err)
			cancelMain()
		}
	}()
	go func() {
		logInfo("Starting TCP server on :%s", config.ListenPort)
		if err := tcpServer.ListenAndServe(); err != nil {
			logError("TCP ListenAndServe: %v", err)
			cancelMain()
		}
	}()

	logInfo("DNS server is running...")

	// Wait for signal or context cancellation
	select {
	case <-sig:
		logInfo("Received signal, shutting down...")
	case <-mainCtx.Done():
		logInfo("Main context cancelled, shutting down...")
	}

	// Initiate shutdown
	cancelMain()

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()

	close(requestQueue)
	workerWG.Wait()

	logInfo("Shutdown complete")
}

func enqueue(queue chan *Request, w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddUint64(&stats.TotalQueries, 1)

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
		logDebug("Request queue full, replied REFUSED")
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

// --- Рекурсивное разрешение с использованием miekg/dns ---

func resolveRecursively(ctx context.Context, name string, qtype uint16, depth int) (*dns.Msg, bool, error) {
	if depth > DefaultMaxRecursionDepth {
		return nil, false, ErrMaxRecursionDepth
	}
	// 1. Запрос к корневым серверам
	msg, auth, err := queryRecursive(ctx, name, qtype, rootServers, nil, depth)
	return msg, auth, err
}

func resolveNameServers(ctx context.Context, nsNames []string, depth int) ([]string, error) {
	if len(nsNames) == 0 {
		return nil, ErrNoNameservers
	}

	var allAddrs []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(nsNames))

	for _, nsName := range nsNames {
		if cachedAddrs := cacheGetNSAddrs(nsName); cachedAddrs != nil {
			mu.Lock()
			allAddrs = append(allAddrs, cachedAddrs...)
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			nsCtx, cancel := context.WithTimeout(ctx, DefaultQueryTimeout)
			defer cancel()

			var minTTL uint32 = uint32(DefaultCacheTTL / time.Second)
			var addrs []string

			aMsg, _, errA := resolveRecursively(nsCtx, name, dns.TypeA, depth+1)
			if errA == nil && aMsg != nil && len(aMsg.Answer) > 0 {
				for _, rr := range aMsg.Answer {
					if a, ok := rr.(*dns.A); ok {
						addrs = append(addrs, fmt.Sprintf("%s:53", a.A.String()))
						if rr.Header().Ttl > 0 && rr.Header().Ttl < minTTL {
							minTTL = rr.Header().Ttl
						}
					}
				}
			}

			if len(addrs) == 0 {
				aaaaMsg, _, errAAAA := resolveRecursively(nsCtx, name, dns.TypeAAAA, depth+1)
				if errAAAA == nil && aaaaMsg != nil && len(aaaaMsg.Answer) > 0 {
					for _, rr := range aaaaMsg.Answer {
						if aaaa, ok := rr.(*dns.AAAA); ok {
							addrs = append(addrs, fmt.Sprintf("[%s]:53", aaaa.AAAA.String()))
							if rr.Header().Ttl > 0 && rr.Header().Ttl < minTTL {
								minTTL = rr.Header().Ttl
							}
						}
					}
				}
			}

			if len(addrs) > 0 {
				cacheSetNSAddrs(name, addrs, minTTL)
				mu.Lock()
				allAddrs = append(allAddrs, addrs...)
				mu.Unlock()
				return
			}

			errChan <- fmt.Errorf("failed to resolve NS %s (A err: %v, AAAA err: %v)", name, errA, nil)
		}(nsName)
	}

	wg.Wait()
	close(errChan)

	if len(allAddrs) > 0 {
		return allAddrs, nil
	}

	if err, ok := <-errChan; ok {
		return nil, err
	}
	return nil, ErrNoNameservers
}

// queryRecursive рекурсивно разрешает имя, опрашивая несколько серверов параллельно
func queryRecursive(ctx context.Context, name string, qtype uint16, servers []string, glueCache map[string][]string, depth int) (*dns.Msg, bool, error) {
	if len(servers) == 0 {
		return nil, false, ErrResolveFailed
	}

	// Создаем запрос один раз
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, true) // Request DNSSEC data

	// Канал для получения первого результата
	resultChan := make(chan struct {
		msg  *dns.Msg
		auth bool // Upstream AD flag
		err  error
	}, 1)

	var wg sync.WaitGroup
	var done int32

	concurrentQueries := DefaultParallelNameServers
	if len(servers) < concurrentQueries {
		concurrentQueries = len(servers)
	}

	for i := 0; i < concurrentQueries; i++ {
		server := servers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()

			if atomic.LoadInt32(&done) == 1 {
				return
			}

			queryCtx, cancel := context.WithTimeout(ctx, DefaultQueryTimeout)
			defer cancel()

			in, _, err := dnsClient.ExchangeContext(queryCtx, m, server)

			if atomic.LoadInt32(&done) == 1 {
				return
			}

			if err != nil {
				logDebug("Parallel query error querying %s for %s %s: %v", server, name, dns.TypeToString[qtype], err)
				return
			}

			if in == nil {
				logDebug("Parallel query nil response from %s for %s %s", server, name, dns.TypeToString[qtype])
				return
			}

			switch in.Rcode {
			case dns.RcodeSuccess:
				hasAnswer := len(in.Answer) > 0
				hasAuthority := len(in.Ns) > 0

				if hasAnswer {
					isAuth := in.AuthenticatedData
					logDebug("Parallel query got answer from %s for %s %s, AD=%v", server, name, dns.TypeToString[qtype], isAuth)
					select {
					case resultChan <- struct {
						msg  *dns.Msg
						auth bool
						err  error
					}{msg: in, auth: isAuth, err: nil}:
						atomic.StoreInt32(&done, 1)
					default:
					}
					return
				} else if hasAuthority {
					isAuth := in.AuthenticatedData
					logDebug("Parallel query got referral/NXDOMAIN from %s for %s %s, AD=%v", server, name, dns.TypeToString[qtype], isAuth)
					select {
					case resultChan <- struct {
						msg  *dns.Msg
						auth bool
						err  error
					}{msg: in, auth: isAuth, err: nil}:
						atomic.StoreInt32(&done, 1)
					default:
					}
					return
				} else {
					logDebug("Parallel query RcodeSuccess but no Answer or Authority from %s for %s %s", server, name, dns.TypeToString[qtype])
					select {
					case resultChan <- struct {
						msg  *dns.Msg
						auth bool
						err  error
					}{msg: in, auth: false, err: nil}:
						atomic.StoreInt32(&done, 1)
					default:
					}
					return
				}

			case dns.RcodeNameError:
				logDebug("Parallel query NXDOMAIN from %s for %s %s", server, name, dns.TypeToString[qtype])
				select {
				case resultChan <- struct {
					msg  *dns.Msg
					auth bool
					err  error
				}{msg: in, auth: false, err: nil}:
					atomic.StoreInt32(&done, 1)
				default:
				}
				return

			case dns.RcodeServerFailure:
				logDebug("Parallel query SERVFAIL from %s for %s %s", server, name, dns.TypeToString[qtype])
				return

			default:
				logDebug("Parallel query Other Rcode %s from %s for %s %s", dns.RcodeToString[in.Rcode], server, name, dns.TypeToString[qtype])
				select {
				case resultChan <- struct {
					msg  *dns.Msg
					auth bool
					err  error
				}{msg: in, auth: false, err: nil}:
					atomic.StoreInt32(&done, 1)
				default:
				}
				return
			}
		}()
	}

	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case res := <-resultChan:
		go func() { <-doneChan }()
		if res.err != nil {
			return nil, false, res.err
		}
		if res.msg == nil {
			return nil, res.auth, ErrResolveFailed
		}

		// Если результат - это referral, обрабатываем его
		if len(res.msg.Answer) == 0 && len(res.msg.Ns) > 0 {
			var nsNames []string
			nsMap := make(map[string]bool)
			for _, ns := range res.msg.Ns {
				if ns.Header().Rrtype == dns.TypeNS {
					nsRecord := ns.(*dns.NS)
					if _, exists := nsMap[nsRecord.Ns]; !exists {
						nsNames = append(nsNames, nsRecord.Ns)
						nsMap[nsRecord.Ns] = true
					}
				}
			}

			if len(nsNames) == 0 {
				logDebug("No NS records found in referral for %s %s", name, dns.TypeToString[qtype])
				return res.msg, res.auth, nil
			}

			cacheSetNS(name, nsNames, 86400) // TODO: Get real TTL

			var nextServers []string
			processedNS := make(map[string]bool)

			if glueCache != nil {
				for _, nsName := range nsNames {
					if addrs, ok := glueCache[nsName]; ok && len(addrs) > 0 {
						nextServers = append(nextServers, addrs...)
						processedNS[nsName] = true
					}
				}
			}

			for _, nsName := range nsNames {
				if processedNS[nsName] {
					continue
				}
				if cachedAddrs := cacheGetNSAddrs(nsName); cachedAddrs != nil {
					nextServers = append(nextServers, cachedAddrs...)
					processedNS[nsName] = true
				}
			}

			glueFromResponse := make(map[string][]string)
			for _, extra := range res.msg.Extra {
				switch extra.Header().Rrtype {
				case dns.TypeA:
					aRecord := extra.(*dns.A)
					for _, nsName := range nsNames {
						if extra.Header().Name == nsName && !processedNS[nsName] {
							addr := fmt.Sprintf("%s:53", aRecord.A.String())
							glueFromResponse[nsName] = append(glueFromResponse[nsName], addr)
							cacheSetNSAddrs(nsName, []string{addr}, extra.Header().Ttl)
						}
					}
				case dns.TypeAAAA:
					aaaaRecord := extra.(*dns.AAAA)
					for _, nsName := range nsNames {
						if extra.Header().Name == nsName && !processedNS[nsName] {
							addr := fmt.Sprintf("[%s]:53", aaaaRecord.AAAA.String())
							glueFromResponse[nsName] = append(glueFromResponse[nsName], addr)
							cacheSetNSAddrs(nsName, []string{addr}, extra.Header().Ttl)
						}
					}
				}
			}

			for nsName, addrs := range glueFromResponse {
				if !processedNS[nsName] && len(addrs) > 0 {
					nextServers = append(nextServers, addrs...)
					processedNS[nsName] = true
				}
			}

			var unresolvedNS []string
			for _, nsName := range nsNames {
				if !processedNS[nsName] {
					unresolvedNS = append(unresolvedNS, nsName)
				}
			}

			if len(unresolvedNS) > 0 {
				logInfo("Need to resolve %d NS names for %s: %v", len(unresolvedNS), name, unresolvedNS)
				resolvedAddrs, err := resolveNameServers(ctx, unresolvedNS, depth)
				if err != nil {
					logError("Failed to resolve some NS names for %s: %v", name, err)
				} else {
					nextServers = append(nextServers, resolvedAddrs...)
				}
			}

			if len(nextServers) > 0 {
				logDebug("Following referral for %s %s to %v (improved)", name, dns.TypeToString[qtype], nextServers)
				newGlueCache := make(map[string][]string)
				for _, extra := range res.msg.Extra {
					switch extra.Header().Rrtype {
					case dns.TypeA:
						aRecord := extra.(*dns.A)
						for _, ns := range res.msg.Ns {
							if ns.Header().Rrtype == dns.TypeNS {
								nsRecord := ns.(*dns.NS)
								if extra.Header().Name == nsRecord.Ns {
									newGlueCache[nsRecord.Ns] = append(newGlueCache[nsRecord.Ns], fmt.Sprintf("%s:53", aRecord.A.String()))
									break
								}
							}
						}
					case dns.TypeAAAA:
						aaaaRecord := extra.(*dns.AAAA)
						for _, ns := range res.msg.Ns {
							if ns.Header().Rrtype == dns.TypeNS {
								nsRecord := ns.(*dns.NS)
								if extra.Header().Name == nsRecord.Ns {
									newGlueCache[nsRecord.Ns] = append(newGlueCache[nsRecord.Ns], fmt.Sprintf("[%s]:53", aaaaRecord.AAAA.String()))
									break
								}
							}
						}
					}
				}
				return queryRecursive(ctx, name, qtype, nextServers, newGlueCache, depth+1)
			} else {
				logError("No referral targets found (even after resolving NS) for %s %s", name, dns.TypeToString[qtype])
				return res.msg, res.auth, nil
			}
		}
		// Иначе возвращаем финальный ответ
		return res.msg, res.auth, nil

	case <-doneChan:
		logError("All parallel queries failed for %s %s", name, dns.TypeToString[qtype])
		return nil, false, ErrResolveFailed

	case <-ctx.Done():
		atomic.StoreInt32(&done, 1)
		go func() { <-doneChan }()
		logError("Parallel query context done for %s %s: %v", name, dns.TypeToString[qtype], ctx.Err())
		if ctx.Err() == context.DeadlineExceeded {
			return nil, false, ErrQueryTimeout
		}
		return nil, false, ctx.Err()
	}
}

// --- Конец рекурсивного разрешения ---

func process(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddUint64(&stats.TotalQueries, 1)

	if len(r.Question) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}

	q := r.Question[0]
	key := fnv64aLower(q.Name) ^ (uint64(q.Qtype) << 32)

	// fast cache hit for final response
	cacheItem := cacheGetEntry(key, CacheTypeFinalResponse)
	if cacheItem != nil {
		atomic.AddUint64(&stats.TotalCacheHits, 1)
		if cachedMsg, ok := cacheItem.Data.(*dns.Msg); ok {
			reply := cachedMsg.Copy()
			reply.Id = r.Id
			reply.Response = true
			// Set AD flag based on the cached upstream AD flag
			if cachedMsg.AuthenticatedData {
				reply.AuthenticatedData = true
			}

			isTCP := false
			if addr := w.RemoteAddr(); addr != nil && addr.Network() == "tcp" {
				isTCP = true
			}
			udpSize := uint16(DefaultUDPSize)
			if isTCP {
				udpSize = DefaultMaxUDPSize
			}
			if !isTCP && reply.Len() > int(udpSize) {
				reply.Truncate(int(udpSize))
			}

			if err := w.WriteMsg(reply); err != nil {
				logError("WriteMsg (cache hit) error: %v", err)
			}
			return
		}
	}
	atomic.AddUint64(&stats.TotalCacheMisses, 1)

	sfKey := strconv.FormatUint(key, 10)

	ch := inflight.DoChan(sfKey, func() (interface{}, error) {
		select {
		case recursionSem <- struct{}{}:
		default:
			return nil, ErrNoRecursionSlot
		}
		start := time.Now()
		defer func() { <-recursionSem }()

		ctx, cancel := context.WithTimeout(context.Background(), DefaultQueryTimeout*4)
		defer cancel()

		resultMsg, isAuth, err := resolveRecursively(ctx, q.Name, q.Qtype, 0)
		latency := time.Since(start)
		logInfo("Resolved %s %s in %v (err=%v, AD=%v)", q.Name, dns.TypeToString[q.Qtype], latency, err, isAuth)

		if err != nil {
			return nil, err
		}
		if resultMsg == nil {
			return nil, ErrResolveFailed
		}

		ttl := uint32(DefaultCacheTTL / time.Second)
		if len(resultMsg.Answer) > 0 {
			for _, rr := range resultMsg.Answer {
				h := rr.Header()
				if h.Ttl > 0 && h.Ttl < ttl {
					ttl = h.Ttl
				}
			}
		} else if len(resultMsg.Ns) > 0 {
			for _, rr := range resultMsg.Ns {
				h := rr.Header()
				if h.Ttl > 0 && h.Ttl < ttl {
					ttl = h.Ttl
				}
			}
		}
		if isAuth && ttl > 300 {
			ttl = 300
		}

		cacheSetEntry(key, resultMsg, CacheTypeFinalResponse, ttl)

		return &upstreamResult{Msg: resultMsg, Auth: isAuth, TTL: ttl}, nil
	})

	resCh := <-ch
	if resCh.Err != nil {
		logInfo("Resolution error for %s %s: %v", q.Name, dns.TypeToString[q.Qtype], resCh.Err)
		reply := new(dns.Msg)
		reply.SetReply(r)
		if errors.Is(resCh.Err, ErrMaxRecursionDepth) || errors.Is(resCh.Err, ErrNoRecursionSlot) {
			reply.SetRcode(r, dns.RcodeRefused)
		} else if errors.Is(resCh.Err, context.DeadlineExceeded) {
			reply.SetRcode(r, dns.RcodeServerFailure)
		} else {
			reply.SetRcode(r, dns.RcodeServerFailure)
		}
		_ = w.WriteMsg(reply)
		return
	}

	ur := resCh.Val.(*upstreamResult)

	reply := ur.Msg.Copy()
	reply.Id = r.Id
	reply.Response = true
	// Set AD flag based on the upstream resolver's AD flag
	if ur.Auth {
		reply.AuthenticatedData = true
		logDebug("Setting AD flag in response for %s %s", q.Name, dns.TypeToString[q.Qtype])
	} else {
		logDebug("NOT setting AD flag in response for %s %s", q.Name, dns.TypeToString[q.Qtype])
	}

	isTCP := false
	if addr := w.RemoteAddr(); addr != nil && addr.Network() == "tcp" {
		isTCP = true
	}
	udpSize := uint16(DefaultUDPSize)
	if isTCP {
		udpSize = DefaultMaxUDPSize
	}
	if !isTCP && reply.Len() > int(udpSize) {
		reply.Truncate(int(udpSize))
	}

	if err := w.WriteMsg(reply); err != nil {
		logError("WriteMsg (final) error: %v", err)
	}
}
