package plugin

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"balancedns/internal/config"

	"github.com/miekg/dns"
)

// TestLuaPluginCNAMELocalData verifies the engine parses local_data.cname and
// produces a Decision carrying the CNAME target, and that cname-only local data
// (no IPs) is accepted (previously it errored "requires ip or ips").
func TestLuaPluginCNAMELocalData(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "cname.lua")
	if err := os.WriteFile(script, []byte(`
function handle(question)
  if question.domain == "redir.example." then
    return {
      action = "LOCAL_DATA",
      local_data = { ttl = 300, cname = "anycast-proxy.example.network." }
    }
  end
  return { action = "FORWARD" }
end
`), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}

	e, err := NewEngine([]config.PluginEntry{{Name: "cname", Runtime: "lua", Path: script}}, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	dec, err := e.Decide(dns.Question{Name: "redir.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != ActionLocalData {
		t.Fatalf("expected LOCAL_DATA, got %s", dec.Action)
	}
	if dec.Local.CNAME != "anycast-proxy.example.network." {
		t.Fatalf("cname = %q, want anycast-proxy.example.network.", dec.Local.CNAME)
	}
	if len(dec.Local.IPs) != 0 {
		t.Fatalf("expected no ips, got %v", dec.Local.IPs)
	}

	// Non-redirected domain forwards.
	dec2, err := e.Decide(dns.Question{Name: "other.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide fwd: %v", err)
	}
	if dec2.Action != ActionForward {
		t.Fatalf("expected FORWARD for non-cname domain, got %s", dec2.Action)
	}
}

// TestLuaPluginCNAMEWithGlue verifies cname + ips is parsed together.
func TestLuaPluginCNAMEWithGlue(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "cname2.lua")
	if err := os.WriteFile(script, []byte(`
function handle(question)
  return {
    action = "LOCAL_DATA",
    local_data = { ttl = 60, cname = "proxy.example.network.", ips = { "31.56.189.225" } }
  }
end
`), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	e, err := NewEngine([]config.PluginEntry{{Name: "cname2", Runtime: "lua", Path: script}}, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	dec, err := e.Decide(dns.Question{Name: "x.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Local.CNAME != "proxy.example.network." {
		t.Fatalf("cname = %q", dec.Local.CNAME)
	}
	if len(dec.Local.IPs) != 1 || dec.Local.IPs[0].String() != "31.56.189.225" {
		t.Fatalf("glue ips = %v", dec.Local.IPs)
	}
}
