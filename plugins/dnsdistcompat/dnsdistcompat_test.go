package dnsdistcompat

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

type testWriter struct {
	msg  *dns.Msg
	addr net.Addr
}

func (w *testWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (w *testWriter) RemoteAddr() net.Addr      { return w.addr }
func (w *testWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *testWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testWriter) Close() error              { return nil }
func (w *testWriter) TsigStatus() error         { return nil }
func (w *testWriter) TsigTimersOnly(bool)       {}
func (w *testWriter) Hijack()                   {}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func newReq(name string, qType uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qType)
	return m
}

func TestBannedIPDrop(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		BannedIPsPath: writeFile(t, dir, "banned.txt", "192.0.2.0/24\n"),
	}
	p := New(cfg)
	w := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53000}}

	handled, err := p.Execute(nil, w, newReq("example.com.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !handled {
		t.Fatal("expected request to be handled (dropped)")
	}
	if w.msg != nil {
		t.Fatal("expected silent drop without DNS response")
	}
}

func TestDropANY(t *testing.T) {
	p := New(Config{})
	w := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 53000}}

	handled, err := p.Execute(nil, w, newReq("example.com.", dns.TypeANY))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !handled {
		t.Fatal("expected ANY query to be dropped")
	}
	if w.msg != nil {
		t.Fatal("expected silent drop without DNS response")
	}
}

func TestSuffixDrop(t *testing.T) {
	p := New(Config{DropSuffixes: []string{"whoami.akamai.net"}})
	w := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.11"), Port: 53000}}

	handled, err := p.Execute(nil, w, newReq("x.whoami.akamai.net.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !handled {
		t.Fatal("expected suffix drop to handle request")
	}
	if w.msg != nil {
		t.Fatal("expected silent drop without DNS response")
	}
}

func TestSpoofFromSuffixLists(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		SNIProxyIPsPath:    writeFile(t, dir, "sni.txt", "203.0.113.9\n"),
		DomainsWithSubPath: writeFile(t, dir, "subs.txt", "example.org\n"),
	}
	p := New(cfg)
	w := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.5"), Port: 53000}}

	handled, err := p.Execute(nil, w, newReq("api.example.org.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !handled {
		t.Fatal("expected spoof match to handle request")
	}
	if w.msg == nil {
		t.Fatal("expected spoof response")
	}
	if got, want := w.msg.Rcode, dns.RcodeSuccess; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected one answer, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A answer, got %T", w.msg.Answer[0])
	}
	if got, want := a.A.String(), "203.0.113.9"; got != want {
		t.Fatalf("unexpected spoof IP: got=%s want=%s", got, want)
	}
}

func TestHostsPolicyAAndAAAA(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		HostsPath: writeFile(t, dir, "hosts.txt", "198.51.100.20 test.local\n"),
	}
	p := New(cfg)
	wA := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.6"), Port: 53000}}
	wAAAA := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.6"), Port: 53000}}

	handledA, err := p.Execute(nil, wA, newReq("test.local.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute A: %v", err)
	}
	if !handledA || wA.msg == nil || len(wA.msg.Answer) != 1 {
		t.Fatal("expected A spoof from hosts map")
	}

	handledAAAA, err := p.Execute(nil, wAAAA, newReq("test.local.", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("execute AAAA: %v", err)
	}
	if !handledAAAA {
		t.Fatal("expected AAAA hosts rule to handle request")
	}
	if wAAAA.msg == nil {
		t.Fatal("expected NOERROR response for AAAA hosts rule")
	}
	if got, want := wAAAA.msg.Rcode, dns.RcodeSuccess; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}
	if len(wAAAA.msg.Answer) != 0 {
		t.Fatalf("expected empty AAAA answer, got %d", len(wAAAA.msg.Answer))
	}
}

func TestExactSpoofAndGarbageNXDOMAIN(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		SNIProxyIPsPath: writeFile(t, dir, "sni.txt", "203.0.113.55\n"),
		DomainsPath:     writeFile(t, dir, "domains.txt", "proxy.local\n"),
		GarbagePath:     writeFile(t, dir, "garbage.txt", "trash.local\n"),
	}
	p := New(cfg)

	wSpoof := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 53000}}
	handled, err := p.Execute(nil, wSpoof, newReq("proxy.local.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute spoof: %v", err)
	}
	if !handled || wSpoof.msg == nil || len(wSpoof.msg.Answer) != 1 {
		t.Fatal("expected exact proxy domain spoof response")
	}

	wGarbage := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 53000}}
	handled, err = p.Execute(nil, wGarbage, newReq("trash.local.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute garbage: %v", err)
	}
	if !handled || wGarbage.msg == nil {
		t.Fatal("expected garbage query to be handled with NXDOMAIN")
	}
	if got, want := wGarbage.msg.Rcode, dns.RcodeNameError; got != want {
		t.Fatalf("unexpected rcode: got=%d want=%d", got, want)
	}
}

func TestLateSuffixDrop(t *testing.T) {
	p := New(Config{LateDropSuffixes: []string{"hotjar.com"}})
	w := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.8"), Port: 53000}}

	handled, err := p.Execute(nil, w, newReq("a.hotjar.com.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !handled {
		t.Fatal("expected late suffix drop to handle request")
	}
	if w.msg != nil {
		t.Fatal("expected silent drop without DNS response")
	}
}

func TestPassWhenNoRuleMatches(t *testing.T) {
	p := New(Config{})
	w := &testWriter{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 53000}}

	handled, err := p.Execute(nil, w, newReq("unmatched.example.", dns.TypeA))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if handled {
		t.Fatal("expected request to pass through")
	}
	if w.msg != nil {
		t.Fatal("did not expect plugin response for pass-through request")
	}
}
