package odoh

import (
	"crypto/tls"
	"log"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/odoh"
	"dns-resolver/internal/plugins"
)

// Config holds configuration for the ODoH plugin.
type Config struct {
	ODoHAddr       string
	CertFile       string      // Deprecated: use TLSConfig
	KeyFile        string      // Deprecated: use TLSConfig
	TLSConfig      *tls.Config // New field for pre-configured TLS
	DNSProxyAddr   string
	DropANYQueries bool
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
	if p.config.TLSConfig == nil {
		log.Printf("[ODoH Plugin] DoH/ODoH disabled: tls config unavailable (odoh_addr=%s)", p.config.ODoHAddr)
		return
	}

	// 2. Start DoH/ODoH server
	log.Printf("[ODoH Plugin] Starting DoH/ODoH server on %s...", p.config.ODoHAddr)
	srv, err := odoh.NewServer(p.config.ODoHAddr, p.config.TLSConfig, p.config.DNSProxyAddr, p.pm, p.m, p.config.DropANYQueries)
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
