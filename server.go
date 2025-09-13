package resolver

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"time"
)

type Server struct {
	resolver *Resolver
	cache    *DNSCache
}

type DNSCache struct {
	mu    sync.RWMutex
	items map[string]*cacheEntry
}

type cacheEntry struct {
	msg      *dns.Msg
	expires  time.Time
	dsRecord []dns.DS
}

func NewServer() *Server {
	return &Server{
		resolver: NewResolver(),
		cache: &DNSCache{
			items: make(map[string]*cacheEntry),
		},
	}
}

func (s *Server) Start() error {
	dns.HandleFunc(".", s.handleDNS)

	server := &dns.Server{
		Addr: ":5355",
		Net:  "udp",
	}

	fmt.Printf("Starting DNS server on port 5355\n")
	return server.ListenAndServe()
}

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false

	// Включаем DNSSEC если запрошено
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(4096, opt.Do())
	}

	// Проверяем кэш перед резолвингом
	if cached := s.cache.get(r.Question[0]); cached != nil {
		w.WriteMsg(cached)
		return
	}

	// Выполняем резолвинг
	resp := s.resolver.Exchange(context.Background(), r)
	if resp.HasError() {
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	// Кэшируем ответ
	s.cache.set(r.Question[0], resp.Msg)

	w.WriteMsg(resp.Msg)
}

func (c *DNSCache) get(q dns.Question) *dns.Msg {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s-%d-%d", q.Name, q.Qtype, q.Qclass)
	if entry, exists := c.items[key]; exists && time.Now().Before(entry.expires) {
		return entry.msg.Copy()
	}
	return nil
}

func (c *DNSCache) set(q dns.Question, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := fmt.Sprintf("%s-%d-%d", q.Name, q.Qtype, q.Qclass)
	ttl := uint32(3600) // Значение по умолчанию 1 час

	// Находим минимальный TTL из всех записей
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}

	c.items[key] = &cacheEntry{
		msg:     msg.Copy(),
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}