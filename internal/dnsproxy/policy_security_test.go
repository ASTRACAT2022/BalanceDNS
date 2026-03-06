package dnsproxy

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

type testWriterWithIP struct {
	testResponseWriter
	ip string
}

func (w *testWriterWithIP) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(w.ip), Port: 53000}
}

func TestSecurityDropsANYQueries(t *testing.T) {
	opts := DefaultProxyOptions()
	opts.DropANYQueries = true

	p := NewProxyWithOptions("127.0.0.1:0", &testResolver{}, nil, nil, nil, opts)
	w := &testWriterWithIP{ip: "127.0.0.1"}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)
	p.handleRequest("udp", w, req)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if got, want := w.msg.Rcode, dns.RcodeRefused; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}
}

func TestPolicyRewriteARecord(t *testing.T) {
	opts := DefaultProxyOptions()
	opts.Policy = ProxyPolicyOptions{
		Enabled: true,
		RewriteRules: []ProxyRewriteRule{
			{Domain: "svc.internal", Type: "A", Value: "10.10.10.10", TTL: 60},
		},
	}

	p := NewProxyWithOptions("127.0.0.1:0", nil, nil, nil, nil, opts)
	w := &testWriterWithIP{ip: "127.0.0.1"}

	req := new(dns.Msg)
	req.SetQuestion("svc.internal.", dns.TypeA)
	p.handleRequest("udp", w, req)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if got, want := w.msg.Rcode, dns.RcodeSuccess; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected one answer, got %d", len(w.msg.Answer))
	}
	rr, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", w.msg.Answer[0])
	}
	if got, want := rr.A.String(), "10.10.10.10"; got != want {
		t.Fatalf("unexpected IP: got=%s want=%s", got, want)
	}
}

func TestPolicyLoadBalancerRoundRobin(t *testing.T) {
	opts := DefaultProxyOptions()
	opts.Policy = ProxyPolicyOptions{
		Enabled: true,
		LoadBalancers: []ProxyLoadBalancerRule{
			{
				Domain:   "app.internal",
				Type:     "A",
				Strategy: "round_robin",
				TTL:      20,
				Targets: []ProxyLoadBalancerTarget{
					{Value: "10.0.0.1", Weight: 1},
					{Value: "10.0.0.2", Weight: 1},
				},
			},
		},
	}

	p := NewProxyWithOptions("127.0.0.1:0", nil, nil, nil, nil, opts)
	w1 := &testWriterWithIP{ip: "127.0.0.1"}
	w2 := &testWriterWithIP{ip: "127.0.0.1"}

	req1 := new(dns.Msg)
	req1.SetQuestion("app.internal.", dns.TypeA)
	p.handleRequest("udp", w1, req1)

	req2 := new(dns.Msg)
	req2.SetQuestion("app.internal.", dns.TypeA)
	p.handleRequest("udp", w2, req2)

	if w1.msg == nil || w2.msg == nil {
		t.Fatal("expected responses for load balancer")
	}
	if len(w1.msg.Answer) != 1 || len(w2.msg.Answer) != 1 {
		t.Fatalf("expected one answer in each response")
	}

	a1, ok1 := w1.msg.Answer[0].(*dns.A)
	a2, ok2 := w2.msg.Answer[0].(*dns.A)
	if !ok1 || !ok2 {
		t.Fatalf("expected A records, got %T and %T", w1.msg.Answer[0], w2.msg.Answer[0])
	}
	if a1.A.String() == a2.A.String() {
		t.Fatalf("expected round robin to rotate targets, both responses returned %s", a1.A.String())
	}
}
