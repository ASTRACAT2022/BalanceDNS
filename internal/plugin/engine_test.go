package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"balancedns/internal/config"

	"github.com/miekg/dns"
)

func TestLuaPluginRewrite(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "policy.lua")
	if err := os.WriteFile(script, []byte(`
function handle(question)
  return { action = "REWRITE", rewrite_domain = "example.net.", rewrite_type = "A" }
end
`), 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}

	e, err := NewEngine([]config.PluginEntry{{Name: "lua", Runtime: "lua", Path: script}}, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision, err := e.Decide(dns.Question{Name: "old.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Action != ActionRewrite {
		t.Fatalf("expected rewrite, got %s", decision.Action)
	}
	if decision.Question.Name != "example.net." {
		t.Fatalf("unexpected name: %s", decision.Question.Name)
	}
	if decision.Question.Qtype != dns.TypeA {
		t.Fatalf("unexpected qtype: %d", decision.Question.Qtype)
	}
}

func TestGoExecPluginLocalData(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "plugin.sh")
	content := `#!/bin/sh
printf '{"action":"LOCAL_DATA","local_data":{"ips":["127.0.0.9"],"ttl":30}}'
`
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	e, err := NewEngine([]config.PluginEntry{{Name: "goexec", Runtime: "go_exec", Path: script}}, 5*time.Second)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision, err := e.Decide(dns.Question{Name: "local.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Action != ActionLocalData {
		t.Fatalf("expected local_data, got %s", decision.Action)
	}
	if len(decision.Local.IPs) != 1 || decision.Local.IPs[0].String() != "127.0.0.9" {
		t.Fatalf("unexpected local_data IPs: %+v", decision.Local.IPs)
	}
}

func TestGoExecPluginTimeout(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "slow.sh")
	content := `#!/bin/sh
sleep 1
printf '{"action":"FORWARD"}'
`
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	e, err := NewEngine([]config.PluginEntry{{Name: "slow", Runtime: "go_exec", Path: script}}, 30*time.Millisecond)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	_, err = e.Decide(dns.Question{Name: "slow.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}
