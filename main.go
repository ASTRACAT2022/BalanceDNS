package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/nsmithuk/resolver"
)

const (
	ListenPort    = "5454"
	CacheTTL      = 300 * time.Second
	WorkerPoolSize = 1000
	QueueSize     = 10000
)

type Request struct {
	w dns.ResponseWriter
	r *dns.Msg
}

type CacheItem struct {
	Msg      *dns.Msg
	ExpireAt time.Time
	Auth     bool // DNSSEC authenticated
}

type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]*CacheItem
}

var (
	dnsCache   *DNSCache
	requestQueue chan *Request
	workerPool sync.WaitGroup
)

func init() {
	dnsCache = &DNSCache{
		cache: make(map[string]*CacheItem),
	}
	requestQueue = make(chan *Request, QueueSize)
	
	// Минимальное логирование
	resolver.Query = func(s string) {
		// fmt.Println("Query:", s) // Включить для отладки
	}
}

func main() {
	go cleanupCache()
	
	for i := 0; i < WorkerPoolSize; i++ {
		workerPool.Add(1)
		go worker()
	}
	
	udpServer := &dns.Server{
		Addr:    ":" + ListenPort,
		Net:     "udp",
		Handler: dns.HandlerFunc(enqueueRequest),
		UDPSize: 65535,
	}

	tcpServer := &dns.Server{
		Addr:    ":" + ListenPort,
		Net:     "tcp",
		Handler: dns.HandlerFunc(enqueueRequest),
	}

	fmt.Printf("DNS Recursive Resolver с DNSSEC запущен на порту %s\n", ListenPort)
	fmt.Printf("Worker Pool: %d, Queue Size: %d\n", WorkerPoolSize, QueueSize)

	var servers sync.WaitGroup
	servers.Add(2)
	
	go func() {
		defer servers.Done()
		if err := udpServer.ListenAndServe(); err != nil {
			log.Printf("UDP ошибка: %v", err)
		}
	}()

	go func() {
		defer servers.Done()
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("TCP ошибка: %v", err)
		}
	}()

	servers.Wait()
	workerPool.Wait()
}

func enqueueRequest(w dns.ResponseWriter, r *dns.Msg) {
	select {
	case requestQueue <- &Request{w: w, r: r}:
	default:
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(reply)
	}
}

func worker() {
	defer workerPool.Done()
	
	for req := range requestQueue {
		processRequest(req.w, req.r)
	}
}

func processRequest(w dns.ResponseWriter, r *dns.Msg) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Паника: %v", r)
		}
	}()

	if len(r.Question) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(reply)
		return
	}

	qname := r.Question[0].Name
	qtype := r.Question[0].Qtype
	isTCP := w.RemoteAddr().Network() == "tcp"

	// Проверяем кэш
	cacheKey := fmt.Sprintf("%s:%s", qname, dns.TypeToString[qtype])
	if cached := getFromCache(cacheKey); cached != nil {
		cached.Id = r.Id
		cached.Response = true
		_ = w.WriteMsg(cached)
		return
	}

	// Создаем резолвер
	res := resolver.NewResolver()

	// Создаем сообщение с DO битом
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	
	udpSize := uint16(4096)
	if isTCP {
		udpSize = 65535
	}
	msg.SetEdns0(udpSize, true) // DO бит для DNSSEC

	// Выполняем запрос с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	result := res.Exchange(ctx, msg)
	cancel()

	if result.Err != nil {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(reply)
		return
	}

	// Проверяем DNSSEC аутентификацию (простая проверка)
	isAuthenticated := (result.Auth == 1) // Secure = 1

	// Устанавливаем флаг AD если данные проверены
	if isAuthenticated {
		result.Msg.AuthenticatedData = true
	}

	// Сохраняем в кэш с информацией о DNSSEC
	setCacheWithAuth(cacheKey, result.Msg, isAuthenticated)

	// Отправляем результат
	result.Msg.Id = r.Id
	result.Msg.Response = true
	
	if !isTCP && result.Msg.Len() > 512 {
		result.Msg.Truncate(512)
	}

	_ = w.WriteMsg(result.Msg)
}

func getFromCache(key string) *dns.Msg {
	dnsCache.mu.RLock()
	defer dnsCache.mu.RUnlock()

	if item, exists := dnsCache.cache[key]; exists {
		if time.Now().Before(item.ExpireAt) {
			msgCopy := item.Msg.Copy()
			if item.Auth {
				msgCopy.AuthenticatedData = true
			}
			return msgCopy
		}
	}
	return nil
}

func setCacheWithAuth(key string, msg *dns.Msg, auth bool) {
	dnsCache.mu.Lock()
	defer dnsCache.mu.Unlock()

	ttl := uint32(CacheTTL.Seconds())
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			header := rr.Header()
			if header.Ttl < ttl && header.Ttl > 0 {
				ttl = header.Ttl
			}
		}
	}

	// Для DNSSEC-проверенных записей используем более короткий TTL
	if auth {
		if ttl > 300 {
			ttl = 300 // Максимум 5 минут для DNSSEC
		}
	}

	dnsCache.cache[key] = &CacheItem{
		Msg:      msg.Copy(),
		ExpireAt: time.Now().Add(time.Duration(ttl) * time.Second),
		Auth:     auth,
	}
}

func cleanupCache() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		dnsCache.mu.Lock()
		now := time.Now()
		for key, item := range dnsCache.cache {
			if now.After(item.ExpireAt) {
				delete(dnsCache.cache, key)
			}
		}
		dnsCache.mu.Unlock()
	}
}
