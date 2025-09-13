package resolver

import (
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestDNSCache(t *testing.T) {
	cache := &DNSCache{
		items: make(map[string]*cacheEntry),
	}

	// Создаем тестовый DNS-запрос
	q := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}

	// Создаем тестовый DNS-ответ
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{192, 0, 2, 1},
		},
	}

	// Тестируем установку значения в кэш
	cache.set(q, msg)

	// Проверяем получение значения из кэша
	cachedMsg := cache.get(q)
	if cachedMsg == nil {
		t.Error("Expected cached message, got nil")
	}

	if len(cachedMsg.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(cachedMsg.Answer))
	}

	// Проверяем истечение TTL
	time.Sleep(time.Second)
	cachedMsg = cache.get(q)
	if cachedMsg == nil {
		t.Error("Cache entry expired too early")
	}
}

func TestServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Fatal("Failed to create server")
	}

	if server.resolver == nil {
		t.Error("Server resolver is nil")
	}

	if server.cache == nil {
		t.Error("Server cache is nil")
	}
}