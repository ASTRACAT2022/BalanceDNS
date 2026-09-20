package config

import "testing"

// TestLoadThreatExampleConfig ensures the shipped prod-threat-example.lua parses
// and validates: threat block, plugins.block_rcode, feeds all accepted by the
// loader/validator.
func TestLoadThreatExampleConfig(t *testing.T) {
	cfg, err := Load("../../configs/prod-threat-example.lua")
	if err != nil {
		t.Fatalf("load prod-threat-example.lua: %v", err)
	}
	if cfg.Plugins.BlockRcode != "NXDOMAIN" {
		t.Fatalf("block_rcode = %q, want NXDOMAIN", cfg.Plugins.BlockRcode)
	}
	if cfg.Threat == nil {
		t.Fatal("threat block not parsed")
	}
	if !cfg.Threat.Enabled {
		t.Fatal("threat.enabled should be true")
	}
	if len(cfg.Threat.Feeds) != 2 {
		t.Fatalf("feeds = %d, want 2", len(cfg.Threat.Feeds))
	}
	if cfg.Threat.Feeds[0].Confidence != "high" {
		t.Fatalf("feed[0].confidence = %q, want high", cfg.Threat.Feeds[0].Confidence)
	}
	// Block action normalized.
	if cfg.Plugins.BlockRcode != "NXDOMAIN" {
		t.Fatalf("unexpected block rcode %q", cfg.Plugins.BlockRcode)
	}
}
