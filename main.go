// main.go
package main

import (
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

	"github.com/golang/groupcache/lru"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

// CacheEntry представляет запись в кэше
type CacheEntry struct {
	Msg      *dns.Msg
	ExpireAt int64 // Unix timestamp
}

// ValidationError ошибка валидации DNSSEC
type ValidationError struct {
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("DNSSEC validation error: %s", e.Reason)
}

// ErrorStats статистика ошибок по доменам
type ErrorStats struct {
	errors map[string]int64
	mutex  sync.RWMutex
}

// DNSHandler обрабатывает DNS-запросы
type DNSHandler struct {
	// Кэши
	cache    *lru.Cache
	cacheMu  sync.RWMutex
	cacheTTL int64

	// Unbound context (libunbound wrapper)
	u *unbound.Unbound

	// Статистика
	errorStats *ErrorStats

	// Метрики
	totalQueries    int64
	cachedQueries   int64
	dnssecQueries   int64
	validationError int64
}

// NewDNSHandler создает новый обработчик
func NewDNSHandler() *DNSHandler {
	h := &DNSHandler{
		cache:    lru.New(30000),
		cacheTTL: 300,
		errorStats: &ErrorStats{
			errors: make(map[string]int64),
		},
	}

	// Инициализируем unbound
	u := unbound.New()
	h.u = u

	// Попробуем прочитать /etc/resolv.conf (необязательно)
	if err := u.ResolvConf("/etc/resolv.conf"); err != nil {
		// не критично — просто логируем
		log.Printf("unbound: failed to read /etc/resolv.conf: %v", err)
	}

	// Попробуем загрузить trust anchor (root key) — путь можно задать через UNBOUND_TA_FILE
	taFile := os.Getenv("UNBOUND_TA_FILE")
	if taFile == "" {
		taFile = "/var/lib/unbound/root.key"
	}
	if _, err := os.Stat(taFile); err == nil {
		if err := u.AddTaFile(taFile); err != nil {
			log.Printf("unbound: AddTaFile(%s) failed: %v", taFile, err)
		} else {
			log.Printf("unbound: loaded trust anchor from %s", taFile)
		}
	} else {
		log.Printf("unbound: trust anchor file not found at %s (consider running unbound-anchor or set UNBOUND_TA_FILE)", taFile)
	}

	// Опционально можно установить дополнительные опции через u.SetOption(...)
	// Например: u.SetOption("num-threads", "2")

	// Запускаем периодический вывод метрик и ошибок
	go h.printMetrics()
	go h.printErrorSummary()

	return h
}

func (h *DNSHandler) printMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
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
		log.Printf("METRICS - Total: %d, Cached: %d (%.2f%%), DNSSEC: %.2f%%, Validation Errors: %.2f%%",
			total, cached, cacheHitRate, dnssecRate, validationErrRate)
	}
}

func (h *DNSHandler) printErrorSummary() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.errorStats.mutex.Lock()
		if len(h.errorStats.errors) > 0 {
			log.Printf("ERROR SUMMARY - Top problematic domains:")
			type de struct {
				d string
				c int64
			}
			var arr []de
			for d, c := range h.errorStats.errors {
				arr = append(arr, de{d, c})
			}
			sort.Slice(arr, func(i, j int) bool { return arr[i].c > arr[j].c })
			for i := 0; i < len(arr) && i < 10; i++ {
				log.Printf("  %s: %d errors", arr[i].d, arr[i].c)
			}
			h.errorStats.errors = make(map[string]int64)
		}
		h.errorStats.mutex.Unlock()
	}
}

func (h *DNSHandler) recordError(domain string) {
	h.errorStats.mutex.Lock()
	h.errorStats.errors[domain]++
	h.errorStats.mutex.Unlock()
}

func (h *DNSHandler) getCacheKey(name string, qtype uint16, dnssec bool) string {
	if dnssec {
		return name + "|" + fmt.Sprintf("%d|dnssec", qtype)
	}
	return name + "|" + fmt.Sprintf("%d", qtype)
}

func (h *DNSHandler) isExpired(exp int64) bool {
	return time.Now().Unix() > exp
}

func (h *DNSHandler) getCachedResponse(key string, req *dns.Msg) *dns.Msg {
	h.cacheMu.RLock()
	v, ok := h.cache.Get(key)
	h.cacheMu.RUnlock()
	if !ok {
		return nil
	}
	entry := v.(*CacheEntry)
	if h.isExpired(entry.ExpireAt) {
		h.cacheMu.Lock()
		h.cache.Remove(key)
		h.cacheMu.Unlock()
		return nil
	}
	msg := entry.Msg.Copy()
	msg.Id = req.Id

	// copy EDNS0 options from request
	if edns0 := req.IsEdns0(); edns0 != nil {
		newOpt := new(dns.OPT)
		newOpt.Hdr.Name = "."
		newOpt.Hdr.Rrtype = dns.TypeOPT
		newOpt.SetUDPSize(edns0.UDPSize())
		newOpt.SetDo(edns0.Do())
		msg.Extra = append(msg.Extra, newOpt)
	}

	// update TTLs based on expireAt
	timeLeft := entry.ExpireAt - time.Now().Unix()
	if timeLeft < 0 {
		timeLeft = 0
	}
	ttl := uint32(timeLeft)
	for _, rr := range msg.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}

	atomic.AddInt64(&h.cachedQueries, 1)
	return msg
}

func (h *DNSHandler) cacheResponse(key string, msg *dns.Msg) {
	// determine min TTL
	minTTL := int64(300)
	if msg.Rcode == dns.RcodeNameError {
		minTTL = 30
	} else {
		for _, sec := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
			for _, rr := range sec {
				if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl > 0 && int64(rr.Header().Ttl) < minTTL {
					minTTL = int64(rr.Header().Ttl)
				}
			}
		}
	}
	if minTTL > 86400 {
		minTTL = 86400
	}

	cached := msg.Copy()
	// remove OPT before caching
	extra := make([]dns.RR, 0, len(cached.Extra))
	for _, rr := range cached.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	cached.Extra = extra
	exp := time.Now().Unix() + minTTL

	h.cacheMu.Lock()
	h.cache.Add(key, &CacheEntry{Msg: cached, ExpireAt: exp})
	h.cacheMu.Unlock()
}

// resolveUsingUnbound использует libunbound для рекурсивного резолвинга (и для DNSSEC)
func (h *DNSHandler) resolveUsingUnbound(name string, qtype uint16, wantDNSSEC bool) (*dns.Msg, error) {
	// unbound expects fully-qualified name with trailing dot
	qname := dns.Fqdn(name)
	if wantDNSSEC {
		atomic.AddInt64(&h.dnssecQueries, 1)
	}

	res, err := h.u.Resolve(qname, qtype, dns.ClassINET)
	if err != nil {
		// Unbound может вернуть ошибку если что-то не так с libunbound
		return nil, fmt.Errorf("unbound resolve error: %v", err)
	}
	if res == nil {
		return nil, fmt.Errorf("unbound returned nil result")
	}

	// Если Unbound пометил как Bogus -> DNSSEC fail
	if res.Bogus {
		atomic.AddInt64(&h.validationError, 1)
		return nil, &ValidationError{Reason: res.WhyBogus}
	}

	// Если есть full answer packet — используем его
	if res.AnswerPacket != nil {
		// Устанавливаем AD флаг если secure
		if res.Secure {
			res.AnswerPacket.MsgHdr.AuthenticatedData = true
		} else {
			res.AnswerPacket.MsgHdr.AuthenticatedData = false
		}
		return res.AnswerPacket.Copy(), nil
	}

	// Если AnswerPacket отсутствует, но есть Rr (parsed RRs) — сформируем сообщение
	if len(res.Rr) > 0 {
		msg := new(dns.Msg)
		msg.SetReply(&dns.Msg{MsgHdr: dns.MsgHdr{Id: 0}})
		msg.Authoritative = false
		msg.RecursionAvailable = false
		msg.Rcode = dns.RcodeSuccess
		msg.Answer = res.Rr
		if res.Secure {
			msg.MsgHdr.AuthenticatedData = true
		}
		return msg, nil
	}

	// NXDOMAIN
	if res.NxDomain {
		m := new(dns.Msg)
		m.SetRcode(&dns.Msg{}, dns.RcodeNameError)
		return m, nil
	}

	return nil, fmt.Errorf("unbound: no data for %s (type %d)", name, qtype)
}

// ServeDNS обрабатывает входящие DNS-запросы
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	atomic.AddInt64(&h.totalQueries, 1)

	// Проверка наличия вопроса
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	domain := question.Name

	// DNSSEC запрошен?
	dnssecRequested := false
	if edns0 := r.IsEdns0(); edns0 != nil && edns0.Do() {
		dnssecRequested = true
	}

	cacheKey := h.getCacheKey(domain, question.Qtype, dnssecRequested)
	if cached := h.getCachedResponse(cacheKey, r); cached != nil {
		w.WriteMsg(cached)
		return
	}

	// Используем unbound для резолва (он делает рекурсивную работу + валидацию)
	resp, err := h.resolveUsingUnbound(domain, question.Qtype, dnssecRequested)
	if err != nil {
		h.recordError(domain)
		// Если это DNSSEC-ошибка — вернём SERVFAIL (такое поведение можно менять)
		if _, ok := err.(*ValidationError); ok {
			atomic.AddInt64(&h.validationError, 1)
			log.Printf("DNSSEC validation error for %s: %v", domain, err)
			// Возвратим SERVFAIL
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		// Иные ошибки — логируем и возвращаем SERVFAIL
		log.Printf("resolve error for %s: %v", domain, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// Кэширование и копирование EDNS из запроса
	if resp != nil {
		// Сохраняем в кэш (ключ = qname|type|dnssec)
		h.cacheResponse(cacheKey, resp)

		// Перед записью в сокет — убедимся, что в ответе есть OPT если клиент запросил его
		if edns0 := r.IsEdns0(); edns0 != nil {
			hasOpt := false
			for _, rr := range resp.Extra {
				if rr.Header().Rrtype == dns.TypeOPT {
					hasOpt = true
					break
				}
			}
			if !hasOpt {
				newOpt := new(dns.OPT)
				newOpt.Hdr.Name = "."
				newOpt.Hdr.Rrtype = dns.TypeOPT
				newOpt.SetUDPSize(edns0.UDPSize())
				newOpt.SetDo(edns0.Do())
				resp.Extra = append(resp.Extra, newOpt)
			}
		}

		// Установим правильный ID запроса
		resp.Id = r.Id

		w.WriteMsg(resp)
		return
	}

	// Если попали сюда — что-то странное
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	handler := NewDNSHandler()

	// UDP сервер
	udpSrv := &dns.Server{
		Addr:    ":5353",
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}
	// TCP сервер
	tcpSrv := &dns.Server{
		Addr:    ":5353",
		Net:     "tcp",
		Handler: handler,
	}

	log.Println("Starting DNS server on :5353 (udp/tcp)")
	log.Printf("CPUs: %d", runtime.NumCPU())

	go func() {
		if err := udpSrv.ListenAndServe(); err != nil {
			log.Fatalf("udp server failed: %v", err)
		}
	}()
	go func() {
		if err := tcpSrv.ListenAndServe(); err != nil {
			log.Fatalf("tcp server failed: %v", err)
		}
	}()

	// graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	udpSrv.Shutdown()
	tcpSrv.Shutdown()
	// destroy unbound context
	if handler.u != nil {
		handler.u.Destroy()
	}
	log.Println("Stopped")
}
