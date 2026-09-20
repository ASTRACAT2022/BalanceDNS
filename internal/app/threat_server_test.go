package app

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"balancedns/internal/config"

	"github.com/miekg/dns"
)

// minimalThreatConfig builds a Server with Threat Intelligence enabled and a
// single high-confidence feed, returning the Server ready for resolveDNS checks.
func buildThreatServer(t *testing.T, blockRcode string) *Server {
	t.Helper()
	dir := t.TempDir()
	feed := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(feed, []byte("blocked1.com\nblocked2.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "policy.lua")
	// Use the real threat policy.
	src, rerr := os.ReadFile("../../scripts/threat_intelligence.lua")
	if rerr != nil {
		src = []byte(`function handle(q) local r=threat.lookup(q.domain) if r~=nil and r.block then return {action="BLOCK"} end return {action="FORWARD"} end`)
	}
	if err := os.WriteFile(script, src, 0o644); err != nil {
		t.Fatal(err)
	}

	// A local file feed is not fetchable via HTTPS; instead register a
	// high-confidence custom list and use the on-disk custom blocklist, which
	// the updater loads without network.
	custom := filepath.Join(dir, "custom.txt")
	if err := os.WriteFile(custom, []byte("blocked1.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Listen: config.ListenConfig{DNS: "127.0.0.1:0", Metrics: "127.0.0.1:0"},
		Upstreams: []config.Upstream{{
			Name: "u", Protocol: "udp", Addr: "127.0.0.1:53", Zones: []string{"."}, TimeoutMS: 500,
		}},
		Routing: config.RoutingConfig{Chain: []string{"blacklist", "hosts", "cache", "lua_policy", "upstream"}},
		Cache:   config.CacheConfig{Enabled: false, Capacity: 1000},
		Plugins: config.PluginConfig{
			Enabled:     true,
			TimeoutMS:   20,
			BlockRcode:  blockRcode,
			Entries:     []config.PluginEntry{{Name: "threat", Runtime: "lua", Path: script}},
		},
		Threat: &config.ThreatConfig{
			Enabled:               true,
			DefaultAction:         blockRcode,
			FailMode:              "open",
			DiskCacheDir:          dir,
			CustomBlocklistFile:   custom,
			UpdateIntervalSeconds: 3600,
			Feeds:                 nil,
		},
	}
	cfg.Listen.ReadTimeoutMS = 1000
	cfg.Listen.WriteTimeoutMS = 1000
	cfg.Listen.UDPSize = 1232
	cfg.Plugins.BlockRcode = blockRcode

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// testResolve returns the rcode for a DNS query through resolveDNS.
func testResolve(s *Server, domain string, qtype uint16) int {
	q := new(dns.Msg)
	q.SetQuestion(domain, qtype)
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 53000}
	resp := s.resolveDNS(q, addr, "udp", "")
	if resp == nil {
		return -1 // DROP sentinel
	}
	return resp.Rcode
}

func TestThreatBlockRcodeNXDOMAIN(t *testing.T) {
	s := buildThreatServer(t, "NXDOMAIN")
	// Allowlist/custom: blocked1.com is in the custom blocklist -> should block.
	rc := testResolve(s, "blocked1.com.", dns.TypeA)
	if rc != dns.RcodeNameError {
		t.Fatalf("blocked domain rcode = %d (%s), want NXDOMAIN(%d)", rc, dns.RcodeToString[rc], dns.RcodeNameError)
	}
	// Clean domain must be forwarded (upstream 127.0.0.1:53 unreachable here but
	// the check is that it is NOT blocked; resolveDNS returns SERVFAIL upstream).
	rc2 := testResolve(s, "www.example.com.", dns.TypeA)
	if rc2 == dns.RcodeNameError {
		t.Fatal("clean domain must not be NXDOMAIN-blocked")
	}
}

func TestThreatBlockRcodeRefused(t *testing.T) {
	s := buildThreatServer(t, "REFUSED")
	rc := testResolve(s, "blocked1.com.", dns.TypeA)
	if rc != dns.RcodeRefused {
		t.Fatalf("blocked domain rcode = %d (%s), want REFUSED(%d)", rc, dns.RcodeToString[rc], dns.RcodeRefused)
	}
}
