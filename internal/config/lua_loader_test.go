package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadLuaConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "balancedns.lua")

	if err := os.Setenv("BDNS_DNS_ADDR", ":5533"); err != nil {
		t.Fatalf("set env: %v", err)
	}
	t.Cleanup(func() { _ = os.Unsetenv("BDNS_DNS_ADDR") })

	content := `
return {
  listen = {
    dns = env("BDNS_DNS_ADDR", ":5353"),
    metrics = ":9191",
    read_timeout_ms = 1500,
    write_timeout_ms = 1500,
    reuse_port = true,
    reuse_addr = true,
    udp_size = 1232,
  },
  logging = { level = "debug", log_queries = true },
  upstreams = {
    {
      name = "google-doh",
      protocol = "doh",
      doh_url = "https://dns.google/dns-query",
      zones = { "." },
      timeout_ms = 1200,
    },
  },
  routing = { chain = { "cache", "lua_policy", "upstream" } },
  cache = {
    enabled = true,
    capacity = 10240,
    min_ttl_seconds = 5,
    max_ttl_seconds = 600,
  },
  plugins = {
    enabled = true,
    timeout_ms = 20,
    entries = {
      { name = "lua", runtime = "lua", path = "./policy.lua" },
    },
  },
  blacklist = { domains = { "ads.example" } },
}
`

	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load lua config: %v", err)
	}

	if cfg.Listen.DNS != ":5533" {
		t.Fatalf("expected dns from env, got %s", cfg.Listen.DNS)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Protocol != "doh" {
		t.Fatalf("unexpected upstreams: %+v", cfg.Upstreams)
	}
	if len(cfg.Plugins.Entries) != 1 {
		t.Fatalf("unexpected plugin entries: %+v", cfg.Plugins.Entries)
	}
	if !filepath.IsAbs(cfg.Plugins.Entries[0].Path) {
		t.Fatalf("expected absolute plugin path from lua config, got %s", cfg.Plugins.Entries[0].Path)
	}
}
