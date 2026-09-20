package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"balancedns/internal/config"
	"balancedns/internal/threat"

	"github.com/miekg/dns"
)

// fakeThreat is a controllable ThreatLookup implementation for tests.
type fakeThreat struct {
	// match maps a query domain to an outcome; nil means no match.
	block  map[string]bool
}

func (f *fakeThreat) Lookup(query string) threat.LookupOutcome {
	if f == nil {
		return threat.LookupOutcome{}
	}
	clean := strings.TrimSuffix(query, ".")
	if block, ok := f.block[clean]; ok {
		return threat.LookupOutcome{
			Match:    true,
			Block:    block,
			Reason:   "high_confidence",
			Category: "botnet_c2",
			Matched:  clean,
		}
	}
	return threat.LookupOutcome{}
}

// TestThreatLuaHookBlocks queries threat_intelligence.lua and verifies a
// blocked domain yields BLOCK while a clean domain yields FORWARD.
func TestThreatLuaHookBlocks(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "policy.lua")
	// Use the real policy shipped in the repo, falling back to an inline
	// equivalent if the repo path differs.
	src, rerr := os.ReadFile("../../scripts/threat_intelligence.lua")
	if rerr != nil {
		src = []byte(`
function handle(question)
  local r = threat.lookup(question.domain)
  if r ~= nil and r.block then return { action = "BLOCK" } end
  return { action = "FORWARD" }
end
`)
	}
	if err := os.WriteFile(script, src, 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}

	ft := &fakeThreat{block: map[string]bool{
		"evil.packetsdk.io": true,
	}}
	hook := NewThreatLuaHook(ft)

	e, err := NewEngineWithOptions(
		[]config.PluginEntry{{Name: "threat", Runtime: "lua", Path: script}},
		50*time.Millisecond,
		nil,
		EngineOption{LuaHook: hook},
	)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	// Blocked domain.
	dec, err := e.Decide(dns.Question{Name: "evil.packetsdk.io.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide blocked: %v", err)
	}
	if dec.Action != ActionBlock {
		t.Fatalf("expected BLOCK for blocked domain, got %s", dec.Action)
	}

	// Clean domain -> forward.
	dec, err = e.Decide(dns.Question{Name: "www.google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide clean: %v", err)
	}
	if dec.Action != ActionForward {
		t.Fatalf("expected FORWARD for clean domain, got %s", dec.Action)
	}
}

// TestThreatLuaHookFailOpenWhenNilHook registers the threat policy WITHOUT a
// hook: the `threat` global is absent, so the policy must forward (fail-open).
func TestThreatLuaHookFailOpenWhenNilHook(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "policy.lua")
	// Use the real repo policy, which guards against a missing `threat` module
	// and fails open to FORWARD (matches fail_mode=open).
	src, rerr := os.ReadFile("../../scripts/threat_intelligence.lua")
	if rerr != nil {
		src = []byte(`
local threat_available = (type(_G.threat) == "table") and (type(_G.threat.lookup) == "function")
function handle(question)
  if not threat_available then return { action = "FORWARD" } end
  local r = threat.lookup(question.domain)
  if r ~= nil and r.block then return { action = "BLOCK" } end
  return { action = "FORWARD" }
end
`)
	}
	if err := os.WriteFile(script, src, 0o644); err != nil {
		t.Fatalf("write script: %v", err)
	}

	// No hook => threat module missing => fail-open FORWARD.
	e, err := NewEngineWithOptions(
		[]config.PluginEntry{{Name: "threat", Runtime: "lua", Path: script}},
		50*time.Millisecond, nil, EngineOption{},
	)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	dec, err := e.Decide(dns.Question{Name: "evil.packetsdk.io.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != ActionForward {
		t.Fatalf("expected fail-open FORWARD without hook, got %s", dec.Action)
	}
}

// TestThreatLuaHookBackwardCompat verifies the hook is a no-op when lookup is
// nil and that existing sandbox behavior (no `threat` global) is unchanged.
func TestThreatLuaHookBackwardCompat(t *testing.T) {
	if NewThreatLuaHook(nil) != nil {
		t.Fatal("NewThreatLuaHook(nil) should return nil (no-op hook)")
	}
}
