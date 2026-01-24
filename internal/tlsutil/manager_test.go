package tlsutil

import (
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
