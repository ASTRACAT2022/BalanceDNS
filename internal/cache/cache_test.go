package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheHitAndExpire(t *testing.T) {
	c := New(10, 1, 10)

	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetReply(&dns.Msg{Question: []dns.Question{q}})
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
		A:   []byte{1, 1, 1, 1},
	})

	c.Set(q, msg)
	if _, ok := c.Get(q); !ok {
		t.Fatalf("expected cache hit")
	}

	time.Sleep(1200 * time.Millisecond)
	if _, ok := c.Get(q); ok {
		t.Fatalf("expected cache miss after ttl expiration")
	}
}

func TestCacheEvictsLRU(t *testing.T) {
	c := New(1, 10, 10)

	q1 := dns.Question{Name: "one.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	q2 := dns.Question{Name: "two.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	m := func(name string) *dns.Msg {
		msg := new(dns.Msg)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
			A:   []byte{1, 1, 1, 1},
		})
		return msg
	}

	c.Set(q1, m("one.org."))
	c.Set(q2, m("two.org."))

	if _, ok := c.Get(q1); ok {
		t.Fatalf("expected first item eviction")
	}
	if _, ok := c.Get(q2); !ok {
		t.Fatalf("expected second item to remain")
	}
}

func TestCacheCopiesAndDecrementsTTL(t *testing.T) {
	c := New(10, 0, 60)
	q := dns.Question{Name: "copy.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := makeMsg(q.Name)
	msg.Answer[0].Header().Ttl = 2
	c.Set(q, msg)

	// A caller changing its response after Set must not corrupt the cache.
	msg.Answer[0].Header().Ttl = 99
	time.Sleep(1100 * time.Millisecond)
	cached, ok := c.Get(q)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got := cached.Answer[0].Header().Ttl; got > 1 {
		t.Fatalf("cached TTL = %d, want at most 1 second remaining", got)
	}
	if got := cached.Answer[0].Header().Ttl; got == 99 {
		t.Fatal("cache retained a mutable caller-owned response")
	}
}

func TestCacheDistinguishesQuestionClass(t *testing.T) {
	c := New(10, 1, 60)
	in := dns.Question{Name: "class.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	chaos := in
	chaos.Qclass = dns.ClassCHAOS
	c.Set(in, makeMsg(in.Name))
	if _, ok := c.Get(chaos); ok {
		t.Fatal("cache hit for a different DNS question class")
	}
}

func TestCacheDoesNotStoreZeroTTLOrTruncatedResponse(t *testing.T) {
	c := New(10, 1, 60)
	q := dns.Question{Name: "uncacheable.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	zeroTTL := makeMsg(q.Name)
	zeroTTL.Answer[0].Header().Ttl = 0
	c.Set(q, zeroTTL)
	if _, ok := c.Get(q); ok {
		t.Fatal("zero-TTL response must not be cached")
	}

	truncated := makeMsg(q.Name)
	truncated.Truncated = true
	c.Set(q, truncated)
	if _, ok := c.Get(q); ok {
		t.Fatal("truncated response must not be cached")
	}
}
