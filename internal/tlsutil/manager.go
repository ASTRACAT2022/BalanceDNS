package tlsutil

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

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

	certFile := m.Config.CertFile
	keyFile := m.Config.KeyFile
	if certFile == "" {
		certFile = "cert.pem"
	}
	if keyFile == "" {
		keyFile = "key.pem"
	}

	preferredDomain := ""
	for _, domain := range m.Config.AcmeDomains {
		if d := strings.TrimSpace(domain); d != "" {
			preferredDomain = d
			break
		}
	}

	cert, selected, err := loadBestStaticTLSPair(m.Config, certFile, keyFile, preferredDomain)
	if err == nil {
		if selected.CertPath != certFile || selected.KeyPath != keyFile {
			if syncErr := syncStaticTLSPair(certFile, keyFile, selected.CertPath, selected.KeyPath); syncErr != nil {
				log.Printf("Warning: TLS auto-repair found a valid pair (%s, %s) but failed to sync to configured paths (%s, %s): %v",
					selected.CertPath, selected.KeyPath, certFile, keyFile, syncErr)
			} else {
				log.Printf("TLS auto-repair applied: %s + %s -> %s + %s",
					selected.CertPath, selected.KeyPath, certFile, keyFile)
			}
		}
		return staticTLSConfig(cert), nil
	}

	log.Printf("Warning: no valid static TLS pair found for cert=%s key=%s: %v", certFile, keyFile, err)

	// Fallback: generate self-signed certificate to keep DoT/DoH available.
	hosts := []string{"astracat.dns", "localhost", "127.0.0.1", "::1"}
	if preferredDomain != "" {
		hosts = append([]string{preferredDomain}, hosts...)
	}
	if ensureErr := EnsureCertificate(certFile, keyFile, hosts); ensureErr != nil {
		log.Printf("Warning: failed to ensure/generate fallback certificates: %v", ensureErr)
	}

	cert, loadErr := tls.LoadX509KeyPair(certFile, keyFile)
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load TLS key pair from %s and %s: %w", certFile, keyFile, loadErr)
	}
	log.Printf("Warning: using fallback self-signed certificate at %s (key: %s)", certFile, keyFile)
	return staticTLSConfig(cert), nil
}

func staticTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

// StartHTTPChallengeServer starts the HTTP server for ACME challenges and redirects.
// This is required for HTTP-01 challenges.
func (m *TLSManager) StartHTTPChallengeServer() {
	if !m.Config.AcmeEnabled || m.AcmeManager == nil {
		return
	}

	addr := ":80" // ACME requires port 80.

	redirectHandler := func(w http.ResponseWriter, r *http.Request) {
		target := "https://" + r.Host + r.URL.Path
		if len(r.URL.RawQuery) > 0 {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}

	log.Printf("Starting HTTP Challenge Server on %s", addr)
	go func() {
		err := http.ListenAndServe(addr, m.AcmeManager.HTTPHandler(http.HandlerFunc(redirectHandler)))
		if err != nil {
			log.Printf("Error starting HTTP Challenge Server: %v", err)
		}
	}()
}
