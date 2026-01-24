package dot

import (
	"crypto/tls"
	"log"
	"time"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/miekg/dns"
)

// Server represents a DNS-over-TLS (DoT) server.
type Server struct {
	Addr           string
	TLSConfig      *tls.Config
	UpstreamTarget string // e.g. "127.0.0.1:53"
	Client         *dns.Client
	PM             *plugins.PluginManager
	Metrics        *metrics.Metrics
}

// NewServer creates a new DoT server.
func NewServer(addr string, tlsConfig *tls.Config, upstream string, pm *plugins.PluginManager, m *metrics.Metrics) *Server {
	return &Server{
		Addr:           addr,
		TLSConfig:      tlsConfig,
		UpstreamTarget: upstream,
		PM:             pm,
		Metrics:        m,
		Client: &dns.Client{
			Net:     "tcp", // Upstream usually TCP for reliability, or UDP if local
			Timeout: 2 * time.Second,
		},
	}
}

// Start starts the DoT server.
func (s *Server) Start() error {
	log.Printf("Starting DoT Server on %s (Upstream: %s)", s.Addr, s.UpstreamTarget)

	srv := &dns.Server{
		Addr:      s.Addr,
		Net:       "tcp-tls",
		TLSConfig: s.TLSConfig,
		Handler:   dns.HandlerFunc(s.handleRequest),
	}

	return srv.ListenAndServe()
}

// handleRequest handles incoming DoT queries.
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	// 1. Record Request Metrics
	if s.Metrics != nil && len(r.Question) > 0 {
		qName := r.Question[0].Name
		qType := dns.TypeToString[r.Question[0].Qtype]
		s.Metrics.IncrementQueries(qName)
		s.Metrics.RecordQueryType(qType)
	}

	// 2. Execute Plugins
	if s.PM != nil {
		ctx := &plugins.PluginContext{
			ResponseWriter: w,
			Metrics:        s.Metrics,
		}
		if handled := s.PM.ExecutePlugins(ctx, w, r); handled {
			return // Plugin handled (e.g. blocked)
		}
	}

	// 3. Forward to Upstream
	// DoT is TCP-based, so we likely want to forward via TCP or UDP.
	// Since upstream is local Knot (optimised), UDP is fine, but TCP handles large responses better.
	// We'll trust the client config (default TCP).

	startTime := time.Now()
	resp, _, err := s.Client.Exchange(r, s.UpstreamTarget)
	if err != nil {
		log.Printf("DoT Upstream Error: %v", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// 4. Record Response Metrics
	if s.Metrics != nil && len(r.Question) > 0 {
		latency := time.Since(startTime)
		qName := r.Question[0].Name
		s.Metrics.RecordLatency(qName, latency)
		s.Metrics.RecordResponseCode(dns.RcodeToString[resp.Rcode])
		if resp.Rcode == dns.RcodeNameError {
			s.Metrics.RecordNXDOMAIN(qName)
		}
	}

	w.WriteMsg(resp)
}
