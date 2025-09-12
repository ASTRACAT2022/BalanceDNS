// main.go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	// "net" // Убираем неиспользуемый импорт
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings" // Для strings.Contains
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"log"
	
	"github.com/cornelk/hashmap"
	"github.com/miekg/dns"
	"github.com/peterzen/goresolver"
	"golang.org/x/sync/singleflight"
)

// ... (все константы, переменные, структуры остаются такими же) ...

const (
	// Default constants (can be overridden by flags)
	DefaultListenPort       = "5454"
	DefaultCacheTTL         = 300 * time.Second
	DefaultUDPSize          = 4096
	DefaultMaxUDPSize       = 65535
	DefaultWorkerMultiplier = 5

	DefaultMaxConcurrentRecursions = 500
	DefaultMaxRecursionDepth       = 10
	DefaultQueryTimeout            = 4 * time.Second
	DefaultParallelNameServers     = 3

	DefaultQueueSize = 100_000

	// Cache entry types
	CacheTypeFinalResponse = iota
	CacheTypeNSAddr
	CacheTypeNS
	CacheTypePrefetchedNSAddr

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
	EnableDNSSEC     bool // Новый флаг для включения DNSSEC
}

// CacheItem хранит кэшированный элемент
type CacheItem struct {
	Data            interface{}
	ExpireAt        int64
	Type            int
	IsAuthenticated bool
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
		"198.41.0.4:53",     // a.root-servers.net
		"199.9.14.201:53",   // b.root-servers.net
		"192.33.4.12:53",    // c.root-servers.net
		"199.7.91.13:53",    // d.root-servers.net
		"192.203.230.10:53", // e.root-servers.net
		"192.5.5.241:53",    // f.root-servers.net
		"192.112.36.4:53",   // g.root-servers.net
		"198.97.190.53:53",  // h.root-servers.net
		"192.36.148.17:53",  // i.root-servers.net
		"192.58.128.30:53",  // j.root-servers.net
		"193.0.14.129:53",   // k.root-servers.net
		"199.7.83.42:53",    // l.root-servers.net
		"202.12.27.33:53",   // m.root-servers.net
	}

	// DNS client for outgoing queries
	dnsClient *dns.Client

	// Set to track names currently being resolved to prevent cycles
	resolvingNames sync.Map

	// goresolver instance
	dnssecResolver *goresolver.Resolver
)

// Request wrapper
type Request struct {
	w dns.ResponseWriter
	r *dns.Msg
}

// upstreamResult returned via singleflight
type upstreamResult struct {
	Msg             *dns.Msg
	IsAuthenticated bool
	TTL             uint32
}

var (
	ErrMaxRecursionDepth   = errors.New("maximum recursion depth exceeded")
	ErrNoRecursionSlot     = errors.New("no recursion slot available")
	ErrQueryTimeout        = errors.New("query timeout")
	ErrResolveFailed       = errors.New("resolution failed")
	ErrNoNameservers       = errors.New("no nameservers found or resolved")
	ErrCircularResolve     = errors.New("circular dependency detected during resolution")
	ErrInvalidRequestFormat = errors.New("invalid DNS request format")
	ErrUnsupportedQType    = errors.New("unsupported QTYPE")
	ErrUnsupportedQClass   = errors.New("unsupported QCLASS")
	ErrInvalidQName        = errors.New("invalid QNAME")
	ErrDNSSECValidationFailed = errors.New("DNSSEC validation failed")
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
	if entryType == CacheTypeNSAddr {
		item = cacheGet(key)
		if item != nil && item.Type == CacheTypePrefetchedNSAddr {
			return item
		}
	}
	return nil
}

func cacheSetEntry(key uint64, data interface{}, entryType int, ttl uint32, isAuthenticated bool) {
	expireAt := time.Now().Add(time.Duration(ttl) * time.Second).UnixNano()
	if ttl > uint32(DefaultCacheTTL/time.Second) {
		expireAt = time.Now().Add(DefaultCacheTTL).UnixNano()
	}
	item := &CacheItem{
		Data:            data,
		ExpireAt:        expireAt,
		Type:            entryType,
		IsAuthenticated: isAuthenticated,
	}
	cache.Set(key, item)
}

func cacheGetNSAddrs(nsName string) ([]string, bool) {
	key := fnv64aLower(nsName)
	item := cacheGetEntry(key, CacheTypeNSAddr)
	if item != nil {
		if addrs, ok := item.Data.([]string); ok {
			return addrs, item.IsAuthenticated
		}
	}
	item = cacheGet(key)
	if item != nil && item.Type == CacheTypePrefetchedNSAddr {
		if addrs, ok := item.Data.([]string); ok {
			return addrs, item.IsAuthenticated
		}
	}
	return nil, false
}

func cacheSetNSAddrsWithPrefetch(nsName string, addrs []string, ttl uint32, authorityNS []string, isAuthenticated bool) {
	key := fnv64aLower(nsName)
	cacheSetEntry(key, addrs, CacheTypeNSAddr, ttl, isAuthenticated)

	if len(authorityNS) > 0 {
		go func() {
			select {
			case recursionSem <- struct{}{}:
				defer func() { <-recursionSem }()
			default:
				logDebug("Prefetch: No recursion slot available for %s", nsName)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), DefaultQueryTimeout*2)
			defer cancel()

			var wg sync.WaitGroup
			limit := 3
			if len(authorityNS) < limit {
				limit = len(authorityNS)
			}
			prefetchedCount := 0
			for i := 0; i < limit; i++ {
				nsToPrefetch := authorityNS[i]
				if strings.EqualFold(nsToPrefetch, nsName) {
					continue
				}
				if addrs, _ := cacheGetNSAddrs(nsToPrefetch); addrs != nil {
					continue
				}
				if _, ok := resolvingNames.Load(fnv64aLower(nsToPrefetch)); ok {
					logDebug("Prefetch: Skipping %s due to potential cycle", nsToPrefetch)
					continue
				}

				wg.Add(1)
				prefetchedCount++
				go func(name string) {
					defer wg.Done()
					prefetchCtx, pCancel := context.WithTimeout(ctx, DefaultQueryTimeout)
					defer pCancel()

					logDebug("Prefetching A/AAAA for NS: %s", name)
					var aAddrs, aaaaAddrs []string
					var aErr, aaaaErr error
					var aMinTTL, aaaaMinTTL uint32 = uint32(DefaultCacheTTL / time.Second), uint32(DefaultCacheTTL / time.Second)
					var aAuth, aaaaAuth bool

					var resolveWg sync.WaitGroup
					resolveWg.Add(2)

					go func() {
						defer resolveWg.Done()
						aMsg, aIsAuth, aErrLocal := resolveRecursively(prefetchCtx, name, dns.TypeA, 1)
						aErr = aErrLocal
						aAuth = aIsAuth
						if aErr == nil && aMsg != nil && len(aMsg.Answer) > 0 {
							for _, rr := range aMsg.Answer {
								if a, ok := rr.(*dns.A); ok {
									aAddrs = append(aAddrs, fmt.Sprintf("%s:53", a.A.String()))
									if rr.Header().Ttl > 0 && rr.Header().Ttl < aMinTTL {
										aMinTTL = rr.Header().Ttl
									}
								}
							}
						}
					}()

					go func() {
						defer resolveWg.Done()
						aaaaMsg, aaaaIsAuth, aaaaErrLocal := resolveRecursively(prefetchCtx, name, dns.TypeAAAA, 1)
						aaaaErr = aaaaErrLocal
						aaaaAuth = aaaaIsAuth
						if aaaaErr == nil && aaaaMsg != nil && len(aaaaMsg.Answer) > 0 {
							for _, rr := range aaaaMsg.Answer {
								if aaaa, ok := rr.(*dns.AAAA); ok {
									aaaaAddrs = append(aaaaAddrs, fmt.Sprintf("[%s]:53", aaaa.AAAA.String()))
									if rr.Header().Ttl > 0 && rr.Header().Ttl < aaaaMinTTL {
										aaaaMinTTL = rr.Header().Ttl
									}
								}
							}
						}
					}()

					resolveWg.Wait()

					var allAddrs []string
					var finalTTL uint32
					isPrefetchAuth := aAuth || aaaaAuth
					if len(aAddrs) > 0 {
						allAddrs = append(allAddrs, aAddrs...)
						finalTTL = aMinTTL
					}
					if len(aaaaAddrs) > 0 {
						allAddrs = append(allAddrs, aaaaAddrs...)
						if aaaaMinTTL < finalTTL {
							finalTTL = aaaaMinTTL
						}
					}

					if len(allAddrs) > 0 {
						prefetchKey := fnv64aLower(name)
						cacheSetEntry(prefetchKey, allAddrs, CacheTypePrefetchedNSAddr, finalTTL, isPrefetchAuth)
						logDebug("Prefetched addresses for NS %s: %v (authenticated: %v)", name, allAddrs, isPrefetchAuth)
					} else {
						if aErr != nil || aaaaErr != nil {
							logDebug("Prefetch failed for NS %s: A err=%v, AAAA err=%v", name, aErr, aaaaErr)
						} else {
							logDebug("Prefetch: No A/AAAA found for NS %s", name)
						}
					}
				}(nsToPrefetch)
			}
			if prefetchedCount > 0 {
				done := make(chan struct{})
				go func() {
					wg.Wait()
					close(done)
				}()
				select {
				case <-done:
					logDebug("Prefetching group for %s completed (%d items)", nsName, prefetchedCount)
				case <-ctx.Done():
					logDebug("Prefetching group for %s cancelled or timed out", nsName)
				}
			}
		}()
	}
}

func cacheGetNS(domain string) ([]string, bool) {
	key := fnv64aLower(domain) ^ (uint64(dns.TypeNS) << 32)
	item := cacheGetEntry(key, CacheTypeNS)
	if item != nil {
		if nss, ok := item.Data.([]string); ok {
			return nss, item.IsAuthenticated
		}
	}
	return nil, false
}

func cacheSetNS(domain string, nss []string, ttl uint32, isAuthenticated bool) {
	key := fnv64aLower(domain) ^ (uint64(dns.TypeNS) << 32)
	cacheSetEntry(key, nss, CacheTypeNS, ttl, isAuthenticated)
}

// --- End Cache Helpers ---

// --- Request Validation ---
func validateRequest(r *dns.Msg) error {
	if r == nil || len(r.Question) == 0 {
		return ErrInvalidRequestFormat
	}

	question := r.Question[0]

	if question.Qclass != dns.ClassINET {
		return ErrUnsupportedQClass
	}

	if question.Qtype == 0 || question.Qtype > 65535 {
		return ErrUnsupportedQType
	}

	if question.Name == "" {
		return ErrInvalidQName
	}
	_, valid := dns.IsDomainName(question.Name)
	if !valid {
		return ErrInvalidQName
	}

	return nil
}

// --- End Request Validation ---

// --- DNSSEC Validation using goresolver ---
// validateWithGoResolver validates that a query can be resolved securely using goresolver.
func validateWithGoResolver(ctx context.Context, name string, qtype uint16) (bool, error) {
	if dnssecResolver == nil {
		logError("goresolver not initialized")
		return false, fmt.Errorf("goresolver not initialized")
	}

	logDebug("Attempting DNSSEC validation for %s %s", name, dns.TypeToString[qtype])

	// Создаем контекст с таймаутом для goresolver
	// goresolver не поддерживает context напрямую, но мы можем запустить его в горутине и отменить через канал
	validationResult := make(chan struct {
		err error
	}, 1)

	fqdnName := dns.Fqdn(name)

	go func() {
		var validationErr error

		switch qtype {
		case dns.TypeA, dns.TypeAAAA:
			// Для A/AAAA используем LookupIP
			_, validationErr = dnssecResolver.LookupIP(fqdnName)
		case dns.TypeNS:
			// Для NS используем StrictNSQuery
			_, validationErr = dnssecResolver.StrictNSQuery(fqdnName, qtype)
		default:
			// Для других типов тоже используем StrictNSQuery
			_, validationErr = dnssecResolver.StrictNSQuery(fqdnName, qtype)
		}

		validationResult <- struct{ err error }{err: validationErr}
	}()

	select {
	case res := <-validationResult:
		if res.err != nil {
			logDebug("DNSSEC validation failed for %s %s: %v", name, dns.TypeToString[qtype], res.err)
			return false, ErrDNSSECValidationFailed
		}
		logDebug("DNSSEC validation successful for %s %s", name, dns.TypeToString[qtype])
		return true, nil
	case <-ctx.Done():
		logDebug("DNSSEC validation timeout for %s %s", name, dns.TypeToString[qtype])
		return false, ErrDNSSECValidationFailed // Или ctx.Err()?
	}
}

// --- End DNSSEC Validation ---

func main() {
	flagPort := flag.String("port", DefaultListenPort, "DNS server listen port")
	flagWorkers := flag.Int("workers", DefaultWorkerMultiplier, "Worker multiplier (GOMAXPROCS * workers)")
	flagLogLevel := flag.String("loglevel", "info", "Log level (error, info, debug)")
	flagQueueSize := flag.Int("queuesize", DefaultQueueSize, "Size of the request queue")
	flagEnableDNSSEC := flag.Bool("dnssec", false, "Enable DNSSEC validation")

	flag.Parse()

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

	config = &Config{
		ListenPort:       *flagPort,
		WorkerMultiplier: *flagWorkers,
		LogLevel:         logLevel,
		QueueSize:        *flagQueueSize,
		EnableDNSSEC:     *flagEnableDNSSEC,
	}

	maxProcs := runtime.GOMAXPROCS(0)
	workers := maxProcs * config.WorkerMultiplier
	requestQueue := make(chan *Request, config.QueueSize)

	logInfo("Starting DNS server with config: Port=%s, Workers=%d (GOMAXPROCS=%d * Multiplier=%d), QueueSize=%d, LogLevel=%s, DNSSEC=%v",
		config.ListenPort, workers, maxProcs, config.WorkerMultiplier, config.QueueSize, *flagLogLevel, config.EnableDNSSEC)

	dnsClient = &dns.Client{
		Net: "udp",
	}

	// Инициализируем goresolver, если DNSSEC включен
	if config.EnableDNSSEC {
		logInfo("Initializing goresolver for DNSSEC validation...")
		var err error
		// Передаем пустую строку для использования конфигурации по умолчанию
		dnssecResolver, err = goresolver.NewResolver("")
		if err != nil {
			logError("Failed to initialize goresolver: %v", err)
			config.EnableDNSSEC = false
			logInfo("DNSSEC disabled due to goresolver initialization failure.")
		} else {
			logInfo("goresolver initialized successfully.")
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	mainCtx, cancelMain := context.WithCancel(context.Background())
	defer cancelMain()

	go stats.PrintPeriodically(mainCtx, 10*time.Second)

	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go worker(requestQueue)
	}

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

	select {
	case <-sig:
		logInfo("Received signal, shutting down...")
	case <-mainCtx.Done():
		logInfo("Main context cancelled, shutting down...")
	}

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
	msg, isAuth, err := queryRecursive(ctx, name, qtype, rootServers, nil, depth)
	return msg, isAuth, err
}

func resolveNameServersWithPrefetch(ctx context.Context, nsNames []string, depth int, authorityNS []string) ([]string, bool, error) {
	if len(nsNames) == 0 {
		return nil, false, ErrNoNameservers
	}

	resultChan := make(chan struct {
		nsName string
		addrs  []string
		isAuth bool
	}, len(nsNames))
	errChan := make(chan error, len(nsNames))
	var wg sync.WaitGroup

	for _, nsName := range nsNames {
		if cachedAddrs, isCachedAuth := cacheGetNSAddrs(nsName); cachedAddrs != nil {
			resultChan <- struct {
				nsName string
				addrs  []string
				isAuth bool
			}{nsName: nsName, addrs: cachedAddrs, isAuth: isCachedAuth}
			continue
		}

		nsKey := fnv64aLower(nsName)
		if _, loaded := resolvingNames.LoadOrStore(nsKey, true); loaded {
			logDebug("Skipping resolution of %s as it's already being resolved (potential cycle)", nsName)
			continue
		}

		wg.Add(1)
		go func(name string, key uint64) {
			defer wg.Done()
			defer resolvingNames.Delete(key)

			nsCtx, cancel := context.WithTimeout(ctx, DefaultQueryTimeout)
			defer cancel()

			subTimeout := DefaultQueryTimeout / 2
			if subTimeout < 500*time.Millisecond {
				subTimeout = 500 * time.Millisecond
			}
			aCtx, aCancel := context.WithTimeout(nsCtx, subTimeout)
			aaaaCtx, aaaaCancel := context.WithTimeout(nsCtx, subTimeout)
			defer aCancel()
			defer aaaaCancel()

			var aAddrs, aaaaAddrs []string
			var aErr, aaaaErr error
			var aMinTTL, aaaaMinTTL uint32 = uint32(DefaultCacheTTL / time.Second), uint32(DefaultCacheTTL / time.Second)
			var aAuth, aaaaAuth bool

			var resolveWg sync.WaitGroup
			resolveWg.Add(2)

			go func() {
				defer resolveWg.Done()
				aMsg, aIsAuth, aErrLocal := resolveRecursively(aCtx, name, dns.TypeA, depth+1)
				aErr = aErrLocal
				aAuth = aIsAuth
				if aErr == nil && aMsg != nil && len(aMsg.Answer) > 0 {
					for _, rr := range aMsg.Answer {
						if a, ok := rr.(*dns.A); ok {
							aAddrs = append(aAddrs, fmt.Sprintf("%s:53", a.A.String()))
							if rr.Header().Ttl > 0 && rr.Header().Ttl < aMinTTL {
								aMinTTL = rr.Header().Ttl
							}
						}
					}
				}
			}()

			go func() {
				defer resolveWg.Done()
				aaaaMsg, aaaaIsAuth, aaaaErrLocal := resolveRecursively(aaaaCtx, name, dns.TypeAAAA, depth+1)
				aaaaErr = aaaaErrLocal
				aaaaAuth = aaaaIsAuth
				if aaaaErr == nil && aaaaMsg != nil && len(aaaaMsg.Answer) > 0 {
					for _, rr := range aaaaMsg.Answer {
						if aaaa, ok := rr.(*dns.AAAA); ok {
							aaaaAddrs = append(aaaaAddrs, fmt.Sprintf("[%s]:53", aaaa.AAAA.String()))
							if rr.Header().Ttl > 0 && rr.Header().Ttl < aaaaMinTTL {
								aaaaMinTTL = rr.Header().Ttl
							}
						}
					}
				}
			}()

			resolveWg.Wait()

			var allAddrs []string
			var finalTTL uint32
			isNSAuth := aAuth || aaaaAuth
			if len(aAddrs) > 0 {
				allAddrs = append(allAddrs, aAddrs...)
				finalTTL = aMinTTL
			}
			if len(aaaaAddrs) > 0 {
				allAddrs = append(allAddrs, aaaaAddrs...)
				if aaaaMinTTL < finalTTL {
					finalTTL = aaaaMinTTL
				}
			}

			if len(allAddrs) > 0 {
				cacheSetNSAddrsWithPrefetch(name, allAddrs, finalTTL, authorityNS, isNSAuth)
				resultChan <- struct {
					nsName string
					addrs  []string
					isAuth bool
				}{nsName: name, addrs: allAddrs, isAuth: isNSAuth}
				return
			}

			if aErr != nil && aaaaErr != nil {
				errChan <- fmt.Errorf("failed to resolve NS %s (A: %v, AAAA: %v)", name, aErr, aaaaErr)
			} else {
				errChan <- fmt.Errorf("resolved NS %s but no A/AAAA records found", name)
			}
		}(nsName, nsKey)
	}

	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	var allResolvedAddrs []string
	resolvedCount := 0
	errorCount := 0
	totalNs := len(nsNames)
	var authStatuses []bool

	collectCtx, collectCancel := context.WithTimeout(ctx, DefaultQueryTimeout)
	defer collectCancel()

collectLoop:
	for resolvedCount+errorCount < totalNs {
		select {
		case res, ok := <-resultChan:
			if !ok {
				break collectLoop
			}
			allResolvedAddrs = append(allResolvedAddrs, res.addrs...)
			authStatuses = append(authStatuses, res.isAuth)
			resolvedCount++
		case _, ok := <-errChan:
			if !ok {
				break collectLoop
			}
			errorCount++
		case <-collectCtx.Done():
			logDebug("Timeout while collecting NS resolution results for %v", nsNames)
			break collectLoop
		}
	}

	isAuthenticated := false
	for _, auth := range authStatuses {
		if auth {
			isAuthenticated = true
			break
		}
	}

	if len(allResolvedAddrs) > 0 {
		return allResolvedAddrs, isAuthenticated, nil
	}

	return nil, false, fmt.Errorf("failed to resolve any of %d NS names", totalNs)
}

// queryRecursive рекурсивно разрешает имя, опрашивая несколько серверов параллельно
func queryRecursive(ctx context.Context, name string, qtype uint16, servers []string, glueCache map[string][]string, depth int) (*dns.Msg, bool, error) {
	if len(servers) == 0 {
		return nil, false, ErrResolveFailed
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	// Включаем EDNS0 для поддержки DNSSEC
	m.SetEdns0(4096, true)

	resultChan := make(chan struct {
		msg    *dns.Msg
		isAuth bool
		err    error
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
				if errors.Is(err, context.DeadlineExceeded) || (err != nil && (strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout"))) {
					logDebug("Parallel query TIMEOUT querying %s for %s %s", server, name, dns.TypeToString[qtype])
				} else {
					logDebug("Parallel query error querying %s for %s %s: %v", server, name, dns.TypeToString[qtype], err)
				}
				return
			}

			if in == nil {
				logDebug("Parallel query nil response from %s for %s %s", server, name, dns.TypeToString[qtype])
				return
			}

			// --- DNSSEC Validation ---
			isAuthenticated := false
			if config.EnableDNSSEC {
				// Проверяем ответ через goresolver
				isValid, validationErr := validateWithGoResolver(queryCtx, name, qtype)
				if validationErr != nil {
					logDebug("DNSSEC validation error for query %s %s: %v", name, dns.TypeToString[qtype], validationErr)
					// Возврат ошибки валидации через канал
					select {
					case resultChan <- struct {
						msg    *dns.Msg
						isAuth bool
						err    error
					}{msg: nil, isAuth: false, err: ErrDNSSECValidationFailed}:
						atomic.StoreInt32(&done, 1)
					default:
					}
					return
				} else if isValid {
					isAuthenticated = true
				}
			}
			// --- End DNSSEC Validation ---

			switch in.Rcode {
			case dns.RcodeSuccess:
				hasAnswer := len(in.Answer) > 0
				hasAuthority := len(in.Ns) > 0

				if hasAnswer {
					logDebug("Parallel query got answer from %s for %s %s (authenticated: %v)", server, name, dns.TypeToString[qtype], isAuthenticated)
					select {
					case resultChan <- struct {
						msg    *dns.Msg
						isAuth bool
						err    error
					}{msg: in, isAuth: isAuthenticated, err: nil}:
						atomic.StoreInt32(&done, 1)
					default:
					}
					return
				} else if hasAuthority {
					logDebug("Parallel query got referral/NXDOMAIN from %s for %s %s (authenticated: %v)", server, name, dns.TypeToString[qtype], isAuthenticated)
					select {
					case resultChan <- struct {
						msg    *dns.Msg
						isAuth bool
						err    error
					}{msg: in, isAuth: isAuthenticated, err: nil}:
						atomic.StoreInt32(&done, 1)
					default:
					}
					return
				} else {
					logDebug("Parallel query RcodeSuccess but no Answer or Authority from %s for %s %s (authenticated: %v)", server, name, dns.TypeToString[qtype], isAuthenticated)
					select {
					case resultChan <- struct {
						msg    *dns.Msg
						isAuth bool
						err    error
					}{msg: in, isAuth: isAuthenticated, err: nil}:
						atomic.StoreInt32(&done, 1)
					default:
					}
					return
				}

			case dns.RcodeNameError:
				logDebug("Parallel query NXDOMAIN from %s for %s %s (authenticated: %v)", server, name, dns.TypeToString[qtype], isAuthenticated)
				select {
				case resultChan <- struct {
					msg    *dns.Msg
					isAuth bool
					err    error
				}{msg: in, isAuth: isAuthenticated, err: nil}:
					atomic.StoreInt32(&done, 1)
				default:
				}
				return

			case dns.RcodeServerFailure:
				logDebug("Parallel query SERVFAIL from %s for %s %s", server, name, dns.TypeToString[qtype])
				select {
				case resultChan <- struct {
					msg    *dns.Msg
					isAuth bool
					err    error
				}{msg: in, isAuth: false, err: nil}:
					atomic.StoreInt32(&done, 1)
				default:
				}
				return

			default:
				logDebug("Parallel query Other Rcode %s from %s for %s %s (authenticated: %v)", dns.RcodeToString[in.Rcode], server, name, dns.TypeToString[qtype], isAuthenticated)
				select {
				case resultChan <- struct {
					msg    *dns.Msg
					isAuth bool
					err    error
				}{msg: in, isAuth: isAuthenticated, err: nil}:
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
			if errors.Is(res.err, ErrDNSSECValidationFailed) {
				logDebug("Returning SERVFAIL due to DNSSEC validation failure")
				return nil, false, ErrDNSSECValidationFailed
			}
			return nil, false, res.err
		}
		if res.msg == nil {
			return nil, res.isAuth, ErrResolveFailed
		}

		if len(res.msg.Answer) == 0 && len(res.msg.Ns) > 0 {
			var nsNames []string
			nsMap := make(map[string]bool)
			for _, ns := range res.msg.Ns {
				if ns.Header().Rrtype == dns.TypeNS {
					nsRecord := ns.(*dns.NS)
					nsName := nsRecord.Ns
					if _, exists := nsMap[nsName]; !exists {
						nsNames = append(nsNames, nsName)
						nsMap[nsName] = true
					}
				}
			}

			if len(nsNames) == 0 {
				logDebug("No NS records found in referral for %s %s (authenticated: %v)", name, dns.TypeToString[qtype], res.isAuth)
				return res.msg, res.isAuth, nil
			}

			nsTTL := uint32(DefaultCacheTTL / time.Second)
			for _, rr := range res.msg.Ns {
				if rr.Header().Ttl > 0 && rr.Header().Ttl < nsTTL {
					nsTTL = rr.Header().Ttl
				}
			}
			if nsTTL > 86400 {
				nsTTL = 86400
			}
			cacheSetNS(name, nsNames, nsTTL, res.isAuth)

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
				if cachedAddrs, _ := cacheGetNSAddrs(nsName); cachedAddrs != nil {
					nextServers = append(nextServers, cachedAddrs...)
					processedNS[nsName] = true
				}
			}

			glueFromResponse := make(map[string][]string)
			for _, extra := range res.msg.Extra {
				if extra.Header().Rrtype != dns.TypeA && extra.Header().Rrtype != dns.TypeAAAA {
					continue
				}
				for _, nsName := range nsNames {
					if dns.IsSubDomain(nsName, extra.Header().Name) || strings.EqualFold(extra.Header().Name, nsName) {
						var addr string
						switch extra.Header().Rrtype {
						case dns.TypeA:
							if a, ok := extra.(*dns.A); ok {
								addr = fmt.Sprintf("%s:53", a.A.String())
							}
						case dns.TypeAAAA:
							if aaaa, ok := extra.(*dns.AAAA); ok {
								addr = fmt.Sprintf("[%s]:53", aaaa.AAAA.String())
							}
						}
						if addr != "" {
							glueFromResponse[nsName] = append(glueFromResponse[nsName], addr)
							glueTTL := extra.Header().Ttl
							if glueTTL == 0 {
								glueTTL = 300
							} else if glueTTL > 86400 {
								glueTTL = 86400
							}
							cacheSetEntry(fnv64aLower(nsName), []string{addr}, CacheTypeNSAddr, glueTTL, res.isAuth)
						}
						break
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
				var authorityNS []string
				for _, ns := range res.msg.Ns {
					if ns.Header().Rrtype == dns.TypeNS {
						authorityNS = append(authorityNS, ns.(*dns.NS).Ns)
					}
				}
				resolvedAddrs, _, err := resolveNameServersWithPrefetch(ctx, unresolvedNS, depth, authorityNS) // Исправлено: убрана isNSAuth
				if err != nil {
					logError("Failed to resolve some NS names for %s: %v", name, err)
				} else {
					nextServers = append(nextServers, resolvedAddrs...)
				}
			}

			if len(nextServers) > 0 {
				logDebug("Following referral for %s %s to %v (authenticated: %v)", name, dns.TypeToString[qtype], nextServers, res.isAuth)
				newGlueCache := make(map[string][]string)
				for nsName, addrs := range glueFromResponse {
					newGlueCache[nsName] = addrs
				}
				if glueCache != nil {
					for k, v := range glueCache {
						newGlueCache[k] = v
					}
				}
				nextMsg, nextAuth, nextErr := queryRecursive(ctx, name, qtype, nextServers, newGlueCache, depth+1)
				return nextMsg, nextAuth, nextErr
			} else {
				logError("No referral targets found (even after resolving NS) for %s %s", name, dns.TypeToString[qtype])
				return res.msg, res.isAuth, nil
			}
		}
		return res.msg, res.isAuth, nil

	case <-doneChan:
		logError("All parallel queries failed for %s %s", name, dns.TypeToString[qtype])
		return nil, false, ErrResolveFailed

	case <-ctx.Done():
		atomic.StoreInt32(&done, 1)
		go func() { <-doneChan }()
		logError("Parallel query context done for %s %s: %v", name, dns.TypeToString[qtype], ctx.Err())
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, false, ErrQueryTimeout
		}
		return nil, false, ctx.Err()
	}
}

// --- Конец рекурсивного разрешения ---

func process(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddUint64(&stats.TotalQueries, 1)

	if err := validateRequest(r); err != nil {
		logDebug("Request validation failed: %v", err)
		reply := new(dns.Msg)
		reply.SetReply(r)
		if errors.Is(err, ErrInvalidRequestFormat) {
			reply.SetRcode(r, dns.RcodeFormatError)
		} else if errors.Is(err, ErrUnsupportedQType) {
			reply.SetRcode(r, dns.RcodeNotImplemented)
		} else if errors.Is(err, ErrUnsupportedQClass) {
			reply.SetRcode(r, dns.RcodeNotImplemented)
		} else if errors.Is(err, ErrInvalidQName) {
			reply.SetRcode(r, dns.RcodeRefused)
		} else {
			reply.SetRcode(r, dns.RcodeFormatError)
		}
		_ = w.WriteMsg(reply)
		return
	}

	q := r.Question[0]
	key := fnv64aLower(q.Name) ^ (uint64(q.Qtype) << 32)

	cacheItem := cacheGetEntry(key, CacheTypeFinalResponse)
	if cacheItem != nil {
		atomic.AddUint64(&stats.TotalCacheHits, 1)
		if cachedMsg, ok := cacheItem.Data.(*dns.Msg); ok {
			reply := cachedMsg.Copy()
			reply.Id = r.Id
			reply.Response = true
			if cacheItem.IsAuthenticated && config.EnableDNSSEC {
				reply.AuthenticatedData = true
				logDebug("Setting AD flag from CACHED authenticated data for %s %s", q.Name, dns.TypeToString[q.Qtype])
			} else {
				reply.AuthenticatedData = false
				logDebug("NOT setting AD flag from CACHED data for %s %s (authenticated: %v, dnssec_enabled: %v)", q.Name, dns.TypeToString[q.Qtype], cacheItem.IsAuthenticated, config.EnableDNSSEC)
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
		logInfo("Resolved %s %s in %v (err=%v, authenticated=%v)", q.Name, dns.TypeToString[q.Qtype], latency, err, isAuth)

		if err != nil {
			if errors.Is(err, ErrDNSSECValidationFailed) {
				logInfo("DNSSEC validation failed for %s %s, returning SERVFAIL", q.Name, dns.TypeToString[q.Qtype])
				return nil, ErrDNSSECValidationFailed
			}
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
		if config.EnableDNSSEC && isAuth && ttl > 300 {
			ttl = 300
		}

		cacheSetEntry(key, resultMsg, CacheTypeFinalResponse, ttl, isAuth)

		return &upstreamResult{Msg: resultMsg, IsAuthenticated: isAuth, TTL: ttl}, nil
	})

	resCh := <-ch
	if resCh.Err != nil {
		logInfo("Resolution error for %s %s: %v", q.Name, dns.TypeToString[q.Qtype], resCh.Err)
		reply := new(dns.Msg)
		reply.SetReply(r)
		if errors.Is(resCh.Err, ErrMaxRecursionDepth) || errors.Is(resCh.Err, ErrNoRecursionSlot) {
			reply.SetRcode(r, dns.RcodeRefused)
		} else if errors.Is(resCh.Err, context.DeadlineExceeded) || errors.Is(resCh.Err, ErrQueryTimeout) {
			reply.SetRcode(r, dns.RcodeServerFailure)
		} else if errors.Is(resCh.Err, ErrCircularResolve) {
			reply.SetRcode(r, dns.RcodeServerFailure)
		} else if errors.Is(resCh.Err, ErrDNSSECValidationFailed) {
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
	if ur.IsAuthenticated && config.EnableDNSSEC {
		reply.AuthenticatedData = true
		logDebug("Setting AD flag in response for %s %s (authenticated)", q.Name, dns.TypeToString[q.Qtype])
	} else {
		reply.AuthenticatedData = false
		logDebug("NOT setting AD flag in response for %s %s (authenticated: %v, dnssec_enabled: %v)", q.Name, dns.TypeToString[q.Qtype], ur.IsAuthenticated, config.EnableDNSSEC)
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
