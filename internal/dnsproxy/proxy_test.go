package dnsproxy

import (
	"net"
	"testing"

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
