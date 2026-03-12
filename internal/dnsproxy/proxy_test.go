package dnsproxy

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dns-resolver/internal/cache"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/plugins/anyblock"

	"github.com/miekg/dns"
)

type testResolver struct {
	resp *dns.Msg
	err  error
}

func (r *testResolver) Resolve(question dns.Question) (*dns.Msg, error) {
	if r.resp != nil {
		cpy := r.resp.Copy()
		cpy.Question = []dns.Question{question}
		return cpy, r.err
	}
	m := new(dns.Msg)
	m.SetRcode(&dns.Msg{Question: []dns.Question{question}}, dns.RcodeSuccess)
	return m, r.err
}

type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (w *testResponseWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (w *testResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *testResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testResponseWriter) Close() error              { return nil }
func (w *testResponseWriter) TsigStatus() error         { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)       {}
func (w *testResponseWriter) Hijack()                   {}

func TestHandleRequestMalformedEmptyQuestion(t *testing.T) {
	p := NewProxy("127.0.0.1:0", &testResolver{}, nil, nil, nil)
	w := &testResponseWriter{}

	p.handleRequest("udp", w, &dns.Msg{})

	if w.msg == nil {
		t.Fatal("expected response for malformed request")
	}
	if got, want := w.msg.Rcode, dns.RcodeFormatError; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}
}

func TestHandleRequestResolverUnavailable(t *testing.T) {
	p := NewProxy("127.0.0.1:0", nil, nil, nil, nil)
	w := &testResponseWriter{}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	p.handleRequest("udp", w, req)

	if w.msg == nil {
		t.Fatal("expected response for resolver unavailable")
	}
	if got, want := w.msg.Rcode, dns.RcodeServerFailure; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}
}

func TestHandleRequestFinalizesHeadersRFCStyle(t *testing.T) {
	resp := new(dns.Msg)
	resp.MsgHdr.Authoritative = true
	resp.MsgHdr.RecursionAvailable = false
	resp.MsgHdr.RecursionDesired = false
	resp.MsgHdr.Id = 999
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("93.184.216.34").To4(),
		},
	}

	p := NewProxy("127.0.0.1:0", &testResolver{resp: resp}, nil, nil, nil)
	w := &testResponseWriter{}

	req := new(dns.Msg)
	req.Id = 12345
	req.RecursionDesired = true
	req.SetQuestion("example.com.", dns.TypeA)
	p.handleRequest("udp", w, req)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Id != req.Id {
		t.Fatalf("response id mismatch: got=%d want=%d", w.msg.Id, req.Id)
	}
	if !w.msg.Response {
		t.Fatal("expected QR bit set")
	}
	if !w.msg.RecursionAvailable {
		t.Fatal("expected RA bit set")
	}
	if !w.msg.RecursionDesired {
		t.Fatal("expected RD bit echoed from request")
	}
	if w.msg.Authoritative {
		t.Fatal("recursive resolver response must not set AA bit")
	}
	if len(w.msg.Question) != 1 || w.msg.Question[0].Name != "example.com." {
		t.Fatalf("unexpected question echo: %+v", w.msg.Question)
	}
}

func TestHandleRequestUDPTruncatesWithoutEDNS(t *testing.T) {
	largeTXT := &dns.TXT{
		Hdr: dns.RR_Header{Name: "big.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{
			strings.Repeat("a", 200),
			strings.Repeat("b", 200),
			strings.Repeat("c", 200),
			strings.Repeat("d", 200),
		},
	}
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{largeTXT}

	p := NewProxy("127.0.0.1:0", &testResolver{resp: resp}, nil, nil, nil)
	w := &testResponseWriter{}

	req := new(dns.Msg)
	req.SetQuestion("big.example.", dns.TypeTXT)
	p.handleRequest("udp", w, req)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	raw, err := w.msg.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	if len(raw) > 512 {
		t.Fatalf("expected UDP response <=512 bytes without EDNS, got %d", len(raw))
	}
	if !w.msg.Truncated {
		t.Fatal("expected TC bit on oversized UDP response")
	}
}

type testRefusedPlugin struct{}

func (p *testRefusedPlugin) Name() string { return "test_refused" }

func (p *testRefusedPlugin) Execute(_ *plugins.PluginContext, w dns.ResponseWriter, r *dns.Msg) (bool, error) {
	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeRefused)
	return true, w.WriteMsg(resp)
}

func (p *testRefusedPlugin) GetConfig() map[string]any { return nil }

func (p *testRefusedPlugin) SetConfig(map[string]any) error { return nil }

func (p *testRefusedPlugin) GetConfigFields() []plugins.ConfigField { return nil }

func TestHandleRequestAnyDropRecordsMetrics(t *testing.T) {
	m := &metrics.Metrics{}
	opts := DefaultProxyOptions()
	opts.DropANYQueries = true

	p := NewProxyWithOptions("127.0.0.1:0", nil, nil, m, nil, opts)
	w := &testResponseWriter{}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)
	p.handleRequest("udp", w, req)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if got, want := w.msg.Rcode, dns.RcodeRefused; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}

	snapshot := m.SnapshotDashboard()
	if got, want := snapshot.TotalQueries, int64(1); got != want {
		t.Fatalf("unexpected total queries: got=%d want=%d", got, want)
	}
	if got, want := typeCount(snapshot.QueryTypes, "ANY"), int64(1); got != want {
		t.Fatalf("unexpected ANY query count: got=%d want=%d", got, want)
	}
	if got, want := codeCount(snapshot.ResponseCodes, dns.RcodeToString[dns.RcodeRefused]), int64(1); got != want {
		t.Fatalf("unexpected REFUSED count: got=%d want=%d", got, want)
	}
}

func TestHandleRequestPluginResponseRecordsMetrics(t *testing.T) {
	m := &metrics.Metrics{}
	pm := plugins.NewPluginManager()
	pm.Register(&testRefusedPlugin{})

	p := NewProxy("127.0.0.1:0", &testResolver{}, pm, m, nil)
	w := &testResponseWriter{}

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.", dns.TypeA)
	p.handleRequest("udp", w, req)

	if w.msg == nil {
		t.Fatal("expected response")
	}
	if got, want := w.msg.Rcode, dns.RcodeRefused; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}

	snapshot := m.SnapshotDashboard()
	if got, want := snapshot.TotalQueries, int64(1); got != want {
		t.Fatalf("unexpected total queries: got=%d want=%d", got, want)
	}
	if got, want := typeCount(snapshot.QueryTypes, "A"), int64(1); got != want {
		t.Fatalf("unexpected A query count: got=%d want=%d", got, want)
	}
	if got, want := codeCount(snapshot.ResponseCodes, dns.RcodeToString[dns.RcodeRefused]), int64(1); got != want {
		t.Fatalf("unexpected REFUSED count: got=%d want=%d", got, want)
	}
}

func TestPreflightAnyBlockPluginRunsBeforePolicyCache(t *testing.T) {
	c, err := cache.NewCache(1, filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	defer c.Close()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)

	pm := plugins.NewPluginManager()
	pm.Register(anyblock.New(true))

	opts := DefaultProxyOptions()
	opts.DropANYQueries = false

	cacheKey := buildDecisionCacheKey(dns.TypeANY, "example.com.")
	c.Set(cacheKey, &cache.Decision{Action: cache.ActionPass}, time.Hour)

	p := NewProxyWithOptions("127.0.0.1:0", &testResolver{}, pm, nil, c, opts)
	w := &testResponseWriter{}

	p.handleRequest("udp", w, req)

	if w.msg != nil {
		t.Fatalf("expected silent drop for ANY preflight plugin, got response rcode=%d", w.msg.Rcode)
	}
}

func typeCount(items []metrics.TypeCount, value string) int64 {
	for _, item := range items {
		if item.Type == value {
			return item.Count
		}
	}
	return 0
}

func codeCount(items []metrics.CodeCount, value string) int64 {
	for _, item := range items {
		if item.Code == value {
			return item.Count
		}
	}
	return 0
}
