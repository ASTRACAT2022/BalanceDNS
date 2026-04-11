package cache

import (
	"fmt"
	"testing"

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
