package cache

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
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
	if got, fresh, ok := c.GetState(q); !ok || fresh || got == nil {
		t.Fatalf("expected stale hit after ttl expiration: ok=%v fresh=%v", ok, fresh)
	}
}

func TestCacheRefreshSingleFlightAndReplace(t *testing.T) {
	c := New(20, 1, 10)
	q := dns.Question{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Configure(time.Second, 0, 2)
	c.Set(q, answer(q.Name, "1.1.1.1", 1))
	time.Sleep(1100 * time.Millisecond)
	var calls atomic.Int32
	done := make(chan struct{})
	for i := 0; i < 1000; i++ {
		c.Refresh(q, func() (*dns.Msg, error) {
			calls.Add(1)
			time.Sleep(20 * time.Millisecond)
			close(done)
			return answer(q.Name, "2.2.2.2", 60), nil
		})
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh did not run")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		m, _, ok := c.GetState(q)
		if ok && m.Answer[0].(*dns.A).A.String() == "2.2.2.2" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls=%d, want 1", calls.Load())
	}
	m, _, ok := c.GetState(q)
	if !ok || m.Answer[0].(*dns.A).A.String() != "2.2.2.2" {
		t.Fatal("successful refresh did not replace old answer")
	}
}

func TestFailedRefreshRetainsLastKnownGood(t *testing.T) {
	c := New(10, 1, 10)
	q := dns.Question{Name: "available.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c.Configure(time.Second, 0, 1)
	c.Set(q, answer(q.Name, "1.1.1.1", 1))
	time.Sleep(1100 * time.Millisecond)
	done := make(chan struct{})
	c.Refresh(q, func() (*dns.Msg, error) { close(done); return nil, errors.New("upstream unavailable") })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh did not run")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.refreshMu.Lock()
		pending := c.refreshing[makeKey(q)]
		c.refreshMu.Unlock()
		if !pending {
			break
		}
		time.Sleep(time.Millisecond)
	}
	m, fresh, ok := c.GetState(q)
	if !ok || fresh || m.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatal("failed refresh discarded the stale answer")
	}
}

func TestPersistentRestoreAndCorruption(t *testing.T) {
	dir := t.TempDir()
	q := dns.Question{Name: "persist.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c := New(10, 1, 10)
	if err := c.SetPersistent(dir); err != nil {
		t.Fatal(err)
	}
	c.Set(q, answer(q.Name, "1.1.1.1", 30))
	c.Close()
	c2 := New(10, 1, 10)
	if err := c2.SetPersistent(dir); err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	m, fresh, ok := c2.GetPersistent(q)
	if !ok || !fresh || m.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("restore failed: ok=%v fresh=%v msg=%v", ok, fresh, m)
	}
	path := c2.recordPath(makeKey(q))
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c2.GetPersistent(q); ok {
		t.Fatal("corrupt record should be ignored")
	}
}

func answer(name, ip string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: []byte{1, 1, 1, 1}}}
	if ip == "2.2.2.2" {
		m.Answer[0].(*dns.A).A = net.ParseIP(ip).To4()
	}
	return m
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
