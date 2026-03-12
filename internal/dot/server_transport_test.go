package dot

import (
	"errors"
	"net"
	"testing"

	"dns-resolver/internal/metrics"

	"github.com/miekg/dns"
)

func TestShouldFallbackTCPOnUpstreamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "overflow", err: errors.New("dns: overflow unpacking uint16"), want: true},
		{name: "timeout string", err: errors.New("i/o timeout"), want: true},
		{name: "temporary net error", err: &net.DNSError{IsTemporary: true}, want: true},
		{name: "other", err: errors.New("connection refused"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldFallbackTCPOnUpstreamError(tt.err)
			if got != tt.want {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestIsRetriableUpstreamError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "timeout net", err: &net.DNSError{IsTimeout: true}, want: true},
		{name: "temporary net", err: &net.DNSError{IsTemporary: true}, want: true},
		{name: "timeout string", err: errors.New("request timeout"), want: true},
		{name: "hard error", err: errors.New("permission denied"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRetriableUpstreamError(tt.err)
			if got != tt.want {
				t.Fatalf("got=%v want=%v", got, tt.want)
			}
		})
	}
}

type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr       { return &net.TCPAddr{} }
func (w *testResponseWriter) RemoteAddr() net.Addr      { return &net.TCPAddr{} }
func (w *testResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *testResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testResponseWriter) Close() error              { return nil }
func (w *testResponseWriter) TsigStatus() error         { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)       {}
func (w *testResponseWriter) Hijack()                   {}

func TestHandleRequestBlocksANYQueries(t *testing.T) {
	m := &metrics.Metrics{}
	s := NewServer("127.0.0.1:0", nil, "127.0.0.1:53", nil, m, true)
	w := &testResponseWriter{}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)
	s.handleRequest(w, req)

	if w.msg == nil {
		t.Fatal("expected DNS response")
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
