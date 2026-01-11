package odoh

import (
	"log"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/odoh"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/tlsutil"
)

// Config holds configuration for the ODoH plugin.
type Config struct {
	ODoHAddr     string
	CertFile     string
	KeyFile      string
	DNSProxyAddr string
}

// Plugin manages the lifecycle of ODoH server.
type Plugin struct {
	config Config
	pm     *plugins.PluginManager
	m      *metrics.Metrics
}

// New creates a new instance of the ODoH plugin.
func New(cfg Config, pm *plugins.PluginManager, m *metrics.Metrics) *Plugin {
	return &Plugin{
		config: cfg,
		pm:     pm,
		m:      m,
	}
}

// Start checks for certificates and starts the server.
func (p *Plugin) Start() {
	if p.config.ODoHAddr == "" {
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
	log.Printf("[ODoH Plugin] Checking TLS certificates (%s, %s)...", cert, key)
	hosts := []string{"astracat.dns", "localhost", "127.0.0.1", "::1"}
	if err := tlsutil.EnsureCertificate(cert, key, hosts); err != nil {
		log.Printf("[ODoH Plugin] Warning: Failed to generate/ensure certificates: %v. HTTPS/TLS might fail.", err)
	}

	// 2. Start ODoH Server
	log.Printf("[ODoH Plugin] Starting ODoH Server on %s...", p.config.ODoHAddr)
	srv, err := odoh.NewServer(p.config.ODoHAddr, cert, key, p.config.DNSProxyAddr, p.pm, p.m)
	if err != nil {
		log.Printf("[ODoH Plugin] Failed to initialize server: %v", err)
		return
	}

	go func() {
		if err := srv.Start(); err != nil {
			log.Printf("[ODoH Plugin] ODoH Server Error: %v", err)
		}
	}()
}
