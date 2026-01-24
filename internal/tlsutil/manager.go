package tlsutil

import (
	"crypto/tls"
	"log"
	"net/http"

	"dns-resolver/internal/config"

	"golang.org/x/crypto/acme/autocert"
)

// TLSManager handles TLS configuration, switching between static certs and ACME.
type TLSManager struct {
	Config      *config.Config
	AcmeManager *autocert.Manager
}

// NewTLSManager creates a new TLSManager.
func NewTLSManager(cfg *config.Config) *TLSManager {
	manager := &TLSManager{
		Config: cfg,
	}

	if cfg.AcmeEnabled {
		manager.AcmeManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.AcmeDomains...),
			Cache:      autocert.DirCache(cfg.AcmeCacheDir),
		}
		if cfg.AcmeEmail != "" {
			manager.AcmeManager.Email = cfg.AcmeEmail
		}
		log.Printf("ACME enabled. Domains: %v, Email: %s, Cache: %s", cfg.AcmeDomains, cfg.AcmeEmail, cfg.AcmeCacheDir)
	}

	return manager
}

// GetTLSConfig returns a tls.Config based on the configuration.
func (m *TLSManager) GetTLSConfig() (*tls.Config, error) {
	if m.Config.AcmeEnabled && m.AcmeManager != nil {
		return &tls.Config{
			GetCertificate: m.AcmeManager.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
			MinVersion:     tls.VersionTLS12,
		}, nil
	}

	// Legacy / Static File Mode
	certFile := m.Config.CertFile
	keyFile := m.Config.KeyFile

	// Default to local files if not specified, matching old logic
	if certFile == "" {
		certFile = "cert.pem"
	}
	if keyFile == "" {
		keyFile = "key.pem"
	}

	// Ensure certificates exist (generate self-signed if needed)
	// We use the existing helper in this package.
	// Defaults for self-signed: localhost, etc.
	hosts := []string{"astracat.dns", "localhost", "127.0.0.1", "::1"}
	if err := EnsureCertificate(certFile, keyFile, hosts); err != nil {
		log.Printf("Warning: Failed to ensure/generate certificates: %v", err)
		// Proceeding, LoadX509KeyPair will likely fail if they don't exist
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// StartHTTPChallengeServer starts the HTTP server for ACME challenges and redirects.
// This is required for HTTP-01 challenges.
func (m *TLSManager) StartHTTPChallengeServer() {
	if !m.Config.AcmeEnabled || m.AcmeManager == nil {
		return
	}

	// Determine address. ACME requires port 80.
	addr := ":80"

	// Redirect handler: Redirects all non-ACME traffic to HTTPS
	redirectHandler := func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.Path
		if len(r.URL.RawQuery) > 0 {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}

	log.Printf("Starting HTTP Challenge Server on %s", addr)
	go func() {
		// manager.HTTPHandler configures the challenge handler.
		// The fallback handler is our redirectHandler.
		err := http.ListenAndServe(addr, m.AcmeManager.HTTPHandler(http.HandlerFunc(redirectHandler)))
		if err != nil {
			log.Printf("Error starting HTTP Challenge Server: %v", err)
		}
	}()
}
