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
