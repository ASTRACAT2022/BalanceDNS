package tlsutil

import (
	"path/filepath"
	"os"
	"testing"

	"dns-resolver/internal/config"
)

func TestNewTLSManager_Static(t *testing.T) {
	cfg := config.NewConfig()
	cfg.AcmeEnabled = false
	cfg.CertFile = "test_cert.pem"
	cfg.KeyFile = "test_key.pem"

	// Cleanup
	defer os.Remove("test_cert.pem")
	defer os.Remove("test_key.pem")

	manager := NewTLSManager(cfg)

	// Since files don't exist, EnsureCertificate (called in GetTLSConfig) should create them
	// mocking EnsureCertificate is hard, but we can rely on the real one since it's integration-ish.
	// But EnsureCertificate is called inside GetTLSConfig.

	tlsConfig, err := manager.GetTLSConfig()
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("TLS Config is nil")
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
}

func TestNewTLSManager_Acme(t *testing.T) {
	cfg := config.NewConfig()
	cfg.AcmeEnabled = true
	cfg.AcmeDomains = []string{"example.com"}
	cfg.AcmeCacheDir = "test_cache"

	// Cleanup
	defer os.RemoveAll("test_cache")

	manager := NewTLSManager(cfg)
	if manager.AcmeManager == nil {
		t.Fatal("AcmeManager should not be nil")
	}

	tlsConfig, err := manager.GetTLSConfig()
	if err != nil {
		t.Fatalf("Failed to get TLS config: %v", err)
	}

	if tlsConfig.GetCertificate == nil {
		t.Error("GetCertificate hook should be set for ACME")
	}
}

func TestTLSAutoRepair_MismatchedConfiguredPair(t *testing.T) {
	tmpDir := t.TempDir()

	configuredCert := filepath.Join(tmpDir, "active", "fullchain.pem")
	configuredKey := filepath.Join(tmpDir, "active", "privkey.pem")
	validCert := filepath.Join(tmpDir, "valid", "fullchain.pem")
	validKey := filepath.Join(tmpDir, "valid", "privkey.pem")
	otherCert := filepath.Join(tmpDir, "other", "fullchain.pem")
	otherKey := filepath.Join(tmpDir, "other", "privkey.pem")

	if err := os.MkdirAll(filepath.Dir(configuredCert), 0o755); err != nil {
		t.Fatalf("mkdir active: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(validCert), 0o755); err != nil {
		t.Fatalf("mkdir valid: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(otherCert), 0o755); err != nil {
		t.Fatalf("mkdir other: %v", err)
	}

	if err := EnsureCertificate(validCert, validKey, []string{"dns.astracat.ru"}); err != nil {
		t.Fatalf("create valid pair: %v", err)
	}
	if err := EnsureCertificate(otherCert, otherKey, []string{"other.example"}); err != nil {
		t.Fatalf("create other pair: %v", err)
	}

	validCertPEM, err := os.ReadFile(validCert)
	if err != nil {
		t.Fatalf("read valid cert: %v", err)
	}
	otherKeyPEM, err := os.ReadFile(otherKey)
	if err != nil {
		t.Fatalf("read other key: %v", err)
	}

	// Create an intentionally broken configured pair.
	if err := os.WriteFile(configuredCert, validCertPEM, 0o644); err != nil {
		t.Fatalf("write configured cert: %v", err)
	}
	if err := os.WriteFile(configuredKey, otherKeyPEM, 0o600); err != nil {
		t.Fatalf("write configured key: %v", err)
	}

	cfg := config.NewConfig()
	cfg.AcmeEnabled = false
	cfg.AcmeDomains = []string{"dns.astracat.ru"}
	cfg.CertFile = configuredCert
	cfg.KeyFile = configuredKey

	origDiscover := discoverStaticTLSCandidates
	discoverStaticTLSCandidates = func(_ *config.Config, certFile, keyFile string) []tlsPairCandidate {
		return []tlsPairCandidate{
			{CertPath: certFile, KeyPath: keyFile}, // broken configured pair
			{CertPath: validCert, KeyPath: validKey},
		}
	}
	defer func() { discoverStaticTLSCandidates = origDiscover }()

	manager := NewTLSManager(cfg)
	tlsConfig, err := manager.GetTLSConfig()
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}
	if tlsConfig == nil || len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected one TLS certificate, got %#v", tlsConfig)
	}

	// Auto-repair should have synced the valid pair into configured paths.
	_, leaf, err := loadAndValidateTLSPair(configuredCert, configuredKey)
	if err != nil {
		t.Fatalf("configured pair is still invalid: %v", err)
	}
	if err := leaf.VerifyHostname("dns.astracat.ru"); err != nil {
		t.Fatalf("configured cert does not match expected domain after repair: %v", err)
	}
}
