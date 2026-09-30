package cache

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func BenchmarkCacheSetGetParallel(b *testing.B) {
	c := New(100000, 5, 600)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			domain := fmt.Sprintf("bench-%d.example.", i%2048)
			q := dns.Question{Name: domain, Qtype: dns.TypeA, Qclass: dns.ClassINET}
			msg := new(dns.Msg)
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{1, 1, 1, 1},
			})
			c.Set(q, msg)
			_, _ = c.Get(q)
			i++
		}
	})
}

func BenchmarkCacheL1Fresh(b *testing.B) {
	c := New(1000, 1, 60)
	q := dns.Question{Name: "fresh.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, makeMsg(q.Name))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.GetState(q)
	}
}

func BenchmarkCacheL1Stale(b *testing.B) {
	c := New(1000, 1, 60)
	q := dns.Question{Name: "stale.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Set(q, makeMsg(q.Name))
	k := makeKey(q)
	s := &c.shards[c.shardIndex(k)]
	s.mu.Lock()
	s.items[k].expiresAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.GetState(q)
	}
}

func BenchmarkCacheL2Restore(b *testing.B) {
	dir, err := os.MkdirTemp("", "balancedns-cache-bench")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dir)
	q := dns.Question{Name: "disk.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	seed := New(10, 1, 60)
	if err = seed.SetPersistent(dir); err != nil {
		b.Fatal(err)
	}
	seed.Set(q, makeMsg(q.Name))
	seed.Close()
	c := New(10, 1, 60)
	if err = c.SetPersistent(dir); err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.GetPersistent(q)
	}
}

func BenchmarkCacheL1Miss(b *testing.B) {
	c := New(10, 1, 60)
	q := dns.Question{Name: "miss.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = c.GetState(q)
	}
}
