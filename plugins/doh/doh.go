package doh

import (
	"log"

	"dns-resolver/internal/doh"
	"dns-resolver/internal/dot"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/tlsutil"
)

// Config holds configuration for the DoH/DoT plugin.
type Config struct {
	DoHAddr      string
	DoTAddr      string
	CertFile     string
	KeyFile      string
	DNSProxyAddr string
}

// Plugin manages the lifecycle of DoH and DoT servers with self-signed cert generation.
type Plugin struct {
	config Config
	pm     *plugins.PluginManager
	m      *metrics.Metrics
}

// New creates a new instance of the DoH/DoT plugin.
func New(cfg Config, pm *plugins.PluginManager, m *metrics.Metrics) *Plugin {
	return &Plugin{
		config: cfg,
		pm:     pm,
		m:      m,
	}
}

// Start checks for certificates (generating if needed) and starts the servers.
func (p *Plugin) Start() {
	if p.config.DoHAddr == "" && p.config.DoTAddr == "" {
		return
	}

	cert := p.config.CertFile
	if cert == "" {
		cert = "cert.pem"
	}
	key := p.config.KeyFile
	if key == "" {
		key = "key.pem"
	}

	// 1. Ensure Certificates exist (Self-Signed if missing)
	log.Printf("[DoH Plugin] Checking TLS certificates (%s, %s)...", cert, key)
	if err := tlsutil.EnsureCertificate(cert, key, "astracat.dns"); err != nil {
		log.Printf("[DoH Plugin] Warning: Failed to generate/ensure certificates: %v. HTTPS/TLS might fail.", err)
	}

	// 2. Start DoH Server
	if p.config.DoHAddr != "" {
		log.Printf("[DoH Plugin] Starting DoH Server on %s...", p.config.DoHAddr)
		srv := doh.NewServer(p.config.DoHAddr, cert, key, p.config.DNSProxyAddr, p.pm, p.m)
		go func() {
			if err := srv.Start(); err != nil {
				log.Printf("[DoH Plugin] DoH Server Error: %v", err)
			}
		}()
	}

	// 3. Start DoT Server
	if p.config.DoTAddr != "" {
		log.Printf("[DoH Plugin] Starting DoT Server on %s...", p.config.DoTAddr)
		srv := dot.NewServer(p.config.DoTAddr, cert, key, p.config.DNSProxyAddr, p.pm, p.m)
		go func() {
			if err := srv.Start(); err != nil {
				log.Printf("[DoH Plugin] DoT Server Error: %v", err)
			}
		}()
	}
}
