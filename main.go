package main

import (
	"container/list"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// ValidationError represents DNSSEC validation error
type ValidationError struct {
	Reason string
	Err    error
}

func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("DNSSEC validation error (%s): %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("DNSSEC validation error: %s", e.Reason)
}

// ErrorStats tracks error statistics
type ErrorStats struct {
	errors map[string]int64
	mutex  sync.RWMutex
}

// DNSHandler handles DNS queries
type DNSHandler struct {
	cache           *LRUCache
	cacheTTL        int64
	cacheMu         sync.RWMutex
	errorStats      *ErrorStats
	totalQueries    int64
	cachedQueries   int64
	dnssecQueries   int64
	validationError int64
	client          *dns.Client
	rootServers     []string
	enableDNSSEC    bool
	strictDNSSEC    bool
}

// NewDNSHandler creates new DNS handler
func NewDNSHandler() *DNSHandler {
	handler := &DNSHandler{
		cache: NewLRUCache(30000),
		cacheTTL: 300,
		errorStats: &ErrorStats{errors: make(map[string]int64)},
		client: &dns.Client{
			Net:          "udp",
			UDPSize:      4096,
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
		},
		rootServers: []string{
			"198.41.0.4:53",    // a.root-servers.net
			"199.9.14.201:53",  // b.root-servers.net
			"192.33.4.12:53",   // c.root-servers.net
			"199.7.91.13:53",   // d.root-servers.net
			"192.203.230.10:53",// e.root-servers.net
			"192.5.5.241:53",   // f.root-servers.net
			"192.112.36.4:53",  // g.root-servers.net
			"198.97.190.53:53", // h.root-servers.net
			"192.36.148.17:53", // i.root-servers.net
			"192.58.128.30:53", // j.root-servers.net
			"193.0.14.129:53",  // k.root-servers.net
			"199.7.83.42:53",   // l.root-servers.net
			"202.12.27.33:53",  // m.root-servers.net
		},
		enableDNSSEC: true,
		strictDNSSEC: true,
	}

	go handler.cleanupCache()
	go handler.printMetrics()
	go handler.printErrorSummary()

	return handler
}

// cleanupCache periodically cleans expired entries
func (h *DNSHandler) cleanupCache() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			h.cacheMu.Lock()
			keysToRemove := make([]string, 0)
			for key, entry := range h.cache.cache {
				if now > entry.expireAt {
					keysToRemove = append(keysToRemove, key)
				}
			}
			for _, key := range keysToRemove {
				h.cache.Remove(key)
			}
			h.cacheMu.Unlock()
		}
	}
}

// printMetrics prints metrics
func (h *DNSHandler) printMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			total := atomic.LoadInt64(&h.totalQueries)
			cached := atomic.LoadInt64(&h.cachedQueries)
			dnssec := atomic.LoadInt64(&h.dnssecQueries)
			validationErr := atomic.LoadInt64(&h.validationError)

			cacheHitRate := float64(0)
			dnssecRate := float64(0)
			validationErrRate := float64(0)
			if total > 0 {
				cacheHitRate = float64(cached) / float64(total) * 100
				dnssecRate = float64(dnssec) / float64(total) * 100
				validationErrRate = float64(validationErr) / float64(total) * 100
			}

			log.Printf("METRICS - Total: %d, Cached: %d (%.2f%%), DNSSEC Queries: %d (%.2f%%), Validation Errors: %d (%.2f%%)",
				total, cached, cacheHitRate, dnssec, dnssecRate, validationErr, validationErrRate)
		}
	}
}

// printErrorSummary prints error summary
func (h *DNSHandler) printErrorSummary() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.errorStats.mutex.Lock()
			if len(h.errorStats.errors) > 0 {
				type domainError struct {
					domain string
					count  int64
				}

				var errors []domainError
				for domain, count := range h.errorStats.errors {
					errors = append(errors, domainError{domain, count})
				}

				sort.Slice(errors, func(i, j int) bool {
					return errors[i].count > errors[j].count
				})

				for i := 0; i < len(errors) && i < 10; i++ {
					log.Printf("  %s: %d errors", errors[i].domain, errors[i].count)
				}

				h.errorStats.errors = make(map[string]int64)
			}
			h.errorStats.mutex.Unlock()
		}
	}
}

// getCacheKey generates cache key
func (h *DNSHandler) getCacheKey(name string, qtype uint16, dnssec bool) string {
	if dnssec {
		return name + "|" + fmt.Sprintf("%d|dnssec", qtype)
	}
	return name + "|" + fmt.Sprintf("%d", qtype)
}

// isExpired checks if cache entry is expired
func (h *DNSHandler) isExpired(expireAt int64) bool {
	return time.Now().Unix() > expireAt
}

// getCachedResponse gets response from cache
func (h *DNSHandler) getCachedResponse(key string, request *dns.Msg) *dns.Msg {
	h.cacheMu.RLock()
	defer h.cacheMu.RUnlock()

	entry, ok := h.cache.Get(key)
	if !ok {
		return nil
	}

	if h.isExpired(entry.expireAt) {
		h.cacheMu.RUnlock()
		h.cacheMu.Lock()
		h.cache.Remove(key)
		h.cacheMu.Unlock()
		h.cacheMu.RLock()
		return nil
	}

	cachedMsg := entry.value.Copy()
	cachedMsg.Id = request.Id

	if edns0 := request.IsEdns0(); edns0 != nil {
		newOpt := new(dns.OPT)
		newOpt.Hdr.Name = "."
		newOpt.Hdr.Rrtype = dns.TypeOPT
		newOpt.SetUDPSize(edns0.UDPSize())
		newOpt.SetDo(edns0.Do())
		cachedMsg.Extra = append(cachedMsg.Extra, newOpt)
	}

	timeLeft := entry.expireAt - time.Now().Unix()
	if timeLeft < 0 {
		timeLeft = 0
	}
	ttlSeconds := uint32(timeLeft)

	for _, rr := range cachedMsg.Answer {
		rr.Header().Ttl = ttlSeconds
	}
	for _, rr := range cachedMsg.Ns {
		rr.Header().Ttl = ttlSeconds
	}
	for _, rr := range cachedMsg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttlSeconds
		}
	}

	atomic.AddInt64(&h.cachedQueries, 1)
	return cachedMsg
}

// cacheResponse caches response
func (h *DNSHandler) cacheResponse(key string, msg *dns.Msg) {
	minTTL := int64(300)
	if msg.Rcode == dns.RcodeNameError {
		minTTL = 30
	} else {
		sections := [][]dns.RR{msg.Answer, msg.Ns, msg.Extra}
		for _, section := range sections {
			for _, rr := range section {
				if rr.Header().Rrtype != dns.TypeOPT && int64(rr.Header().Ttl) < minTTL && rr.Header().Ttl > 0 {
					minTTL = int64(rr.Header().Ttl)
				}
			}
		}
	}

	if minTTL > 86400 {
		minTTL = 86400
	}

	cachedMsg := msg.Copy()
	extra := make([]dns.RR, 0, len(cachedMsg.Extra))
	for _, rr := range cachedMsg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	cachedMsg.Extra = extra

	expireAt := time.Now().Unix() + minTTL

	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	h.cache.Set(key, &CacheEntry{
		value:    cachedMsg,
		expireAt: expireAt,
	})
}

// recordError records error
func (h *DNSHandler) recordError(domain string) {
	h.errorStats.mutex.Lock()
	defer h.errorStats.mutex.Unlock()
	h.errorStats.errors[domain]++
}

// isNormalError checks if error is normal
func (h *DNSHandler) isNormalError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "Refused") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "no answer from DNS server")
}

// queryNS sends query to nameserver
func (h *DNSHandler) queryNS(server string, msg *dns.Msg) (*dns.Msg, error) {
	resp, _, err := h.client.Exchange(msg, server)
	if err != nil {
		if err == dns.ErrBuf || strings.Contains(err.Error(), "overflow") {
			h.client.Net = "tcp"
			resp, _, err = h.client.Exchange(msg, server)
			h.client.Net = "udp"
			return resp, err
		}
		return nil, err
	}

	if resp != nil && resp.Truncated && h.client.Net == "udp" {
		h.client.Net = "tcp"
		resp, _, err = h.client.Exchange(msg, server)
		h.client.Net = "udp"
	}

	return resp, err
}

// getNSServers gets NS servers
func (h *DNSHandler) getNSServers(name string) ([]string, error) {
	resp, err := h.resolve(name, dns.TypeNS, false)
	if err != nil {
		return nil, err
	}

	var servers []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			servers = append(servers, ns.Ns+":53")
		}
	}
	if len(servers) == 0 {
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				servers = append(servers, ns.Ns+":53")
			}
		}
	}
	return servers, nil
}

// verifyDNSSEC verifies DNSSEC (stub)
func (h *DNSHandler) verifyDNSSEC(name string, resp *dns.Msg) error {
	if !h.enableDNSSEC {
		return nil
	}

	atomic.AddInt64(&h.dnssecQueries, 1)

	hasRRSIG := false
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
				break
			}
		}
		if hasRRSIG {
			break
		}
	}

	if !hasRRSIG {
		return &ValidationError{Reason: "No RRSIG records found"}
	}

	log.Printf("DNSSEC verification (stub) successful for %s", name)
	return nil
}

// resolve resolves domain recursively
func (h *DNSHandler) resolve(name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	servers := h.rootServers
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = false

	if dnssec && h.enableDNSSEC {
		m.SetEdns0(4096, true)
	}

	maxDepth := 20
	for depth := 0; depth < maxDepth; depth++ {
		type result struct {
			resp *dns.Msg
			err  error
		}

		results := make(chan result, len(servers))
		var wg sync.WaitGroup

		for _, server := range servers {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				resp, err := h.queryNS(s, m)
				results <- result{resp, err}
			}(server)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		var bestResp *dns.Msg
		for res := range results {
			if res.err != nil {
				if !h.isNormalError(res.err) {
					log.Printf("ERROR querying %s: %v", name, res.err)
				}
				continue
			}

			if res.resp != nil {
				if (res.resp.Rcode == dns.RcodeSuccess && len(res.resp.Answer) > 0) ||
					(res.resp.Rcode == dns.RcodeNameError) {

					if dnssec && h.enableDNSSEC {
						if err := h.verifyDNSSEC(name, res.resp); err != nil {
							atomic.AddInt64(&h.validationError, 1)
							return res.resp, &ValidationError{Reason: "verification failed", Err: err}
						}
					}

					return res.resp, nil
				} else if len(res.resp.Ns) > 0 {
					var newServers []string
					for _, rr := range res.resp.Ns {
						if ns, ok := rr.(*dns.NS); ok {
							newServers = append(newServers, ns.Ns+":53")
						}
					}
					if len(newServers) > 0 {
						servers = newServers
						bestResp = res.resp
						break
					}
				}

				if bestResp == nil {
					bestResp = res.resp
				}
			}
		}

		if bestResp == nil {
			return nil, fmt.Errorf("no response from nameservers for %s", name)
		}
	}

	return nil, fmt.Errorf("recursion depth exceeded for %s", name)
}

// ServeDNS handles DNS requests
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddInt64(&h.totalQueries, 1)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	domain := question.Name
	dnssecRequested := false
	if edns0 := r.IsEdns0(); edns0 != nil && edns0.Do() && h.enableDNSSEC {
		dnssecRequested = true
	}

	cacheKey := h.getCacheKey(domain, question.Qtype, dnssecRequested)
	if cachedResponse := h.getCachedResponse(cacheKey, r); cachedResponse != nil {
		_ = w.WriteMsg(cachedResponse)
		return
	}

	resp, err := h.resolve(domain, question.Qtype, dnssecRequested)

	if err != nil {
		h.recordError(domain)

		if dnssecErr, ok := err.(*ValidationError); ok {
			atomic.AddInt64(&h.validationError, 1)
			log.Printf("DNSSEC validation error for %s: %v", domain, dnssecErr)

			if h.strictDNSSEC {
				m.SetRcode(r, dns.RcodeServerFailure)
				m.AuthenticatedData = false
				_ = w.WriteMsg(m)
				return
			}
		} else if !h.isNormalError(err) {
			log.Printf("ERROR resolving %s: %v", domain, err)
		}

		if resp == nil {
			m.SetRcode(r, dns.RcodeServerFailure)
			m.AuthenticatedData = false
			_ = w.WriteMsg(m)
			return
		}
	}

	if resp != nil {
		m.Answer = resp.Answer
		m.Ns = resp.Ns
		m.Extra = resp.Extra
		m.MsgHdr.RecursionAvailable = resp.MsgHdr.RecursionAvailable
		m.MsgHdr.Response = resp.MsgHdr.Response
		m.MsgHdr.Authoritative = resp.MsgHdr.Authoritative
		m.Rcode = resp.Rcode

		if dnssecRequested {
			_, isDNSSecError := err.(*ValidationError)
			if isDNSSecError {
				m.AuthenticatedData = false
			} else if err == nil {
				m.AuthenticatedData = true
			} else {
				m.AuthenticatedData = false
			}
		} else {
			m.AuthenticatedData = false
		}

		if edns0 := r.IsEdns0(); edns0 != nil {
			hasOpt := false
			for _, rr := range m.Extra {
				if rr.Header().Rrtype == dns.TypeOPT {
					hasOpt = true
					if opt, ok := rr.(*dns.OPT); ok {
						opt.SetDo(edns0.Do())
					}
					break
				}
			}

			if !hasOpt {
				newOpt := new(dns.OPT)
				newOpt.Hdr.Name = "."
				newOpt.Hdr.Rrtype = dns.TypeOPT
				newOpt.SetUDPSize(edns0.UDPSize())
				newOpt.SetDo(edns0.Do())
				m.Extra = append(m.Extra, newOpt)
			}
		}
		
		// Cache the response
		h.cacheResponse(cacheKey, resp)
	} else {
		m.SetRcode(r, dns.RcodeServerFailure)
		m.AuthenticatedData = false
		_ = w.WriteMsg(m)
		return
	}

	_ = w.WriteMsg(m)
}

// CacheEntry represents cache entry
type CacheEntry struct {
	key       string
	value     *dns.Msg
	listEntry *list.Element
	expireAt  int64
}

// LRUCache is a simple LRU cache
type LRUCache struct {
	maxEntries int
	cache      map[string]*CacheEntry
	list       *list.List
	mu         sync.RWMutex
}

func NewLRUCache(size int) *LRUCache {
	return &LRUCache{
		maxEntries: size,
		cache:      make(map[string]*CacheEntry),
		list:       list.New(),
	}
}

func (c *LRUCache) Set(key string, value *CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ce, ok := c.cache[key]; ok {
		c.list.MoveToFront(ce.listEntry)
		ce.value = value.value
		ce.expireAt = value.expireAt
		return
	}

	if len(c.cache) >= c.maxEntries {
		// Remove least recently used item
		if back := c.list.Back(); back != nil {
			removedEntry := c.list.Remove(back)
			if entry, ok := removedEntry.(*CacheEntry); ok {
				delete(c.cache, entry.key)
			}
		}
	}

	// Add new entry
	element := c.list.PushFront(&CacheEntry{
		key:      key,
		value:    value.value,
		expireAt: value.expireAt,
	})
	entry := &CacheEntry{
		key:       key,
		value:     value.value,
		expireAt:  value.expireAt,
		listEntry: element,
	}
	c.cache[key] = entry
}

func (c *LRUCache) Get(key string) (value *CacheEntry, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ce, exists := c.cache[key]; exists {
		c.list.MoveToFront(ce.listEntry)
		return ce, true
	}
	return nil, false
}

func (c *LRUCache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ce, ok := c.cache[key]; ok {
		delete(c.cache, key)
		c.list.Remove(ce.listEntry)
	}
}

// Main execution
func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	handler := NewDNSHandler()

	server := &dns.Server{
		Addr:    ":5353",
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}

	tcpServer := &dns.Server{
		Addr:    ":5353",
		Net:     "tcp",
		Handler: handler,
	}

	log.Println("Starting DNS server on :5353")
	log.Println("Features: Recursive DNS resolution with basic DNSSEC support (stub validation)")
	log.Printf("CPUs: %d", runtime.NumCPU())
	log.Printf("DNSSEC: %v, Strict Mode: %v", handler.enableDNSSEC, handler.strictDNSSEC)

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP server: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down DNS server...")
	_ = server.Shutdown()
	_ = tcpServer.Shutdown()
	log.Println("DNS server stopped")
}
