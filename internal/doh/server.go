package doh

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Server represents a DNS-over-HTTPS server.
type Server struct {
	Addr           string
	CertFile       string
	KeyFile        string
	UpstreamTarget string // e.g. "127.0.0.1:53"
	Client         *dns.Client
	PM             *plugins.PluginManager
	Metrics        *metrics.Metrics
}

// NewServer creates a new DoH server.
func NewServer(addr, certFile, keyFile, upstream string, pm *plugins.PluginManager, m *metrics.Metrics) *Server {
	return &Server{
		Addr:           addr,
		CertFile:       certFile,
		KeyFile:        keyFile,
		UpstreamTarget: upstream,
		PM:             pm,
		Metrics:        m,
		Client: &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
		},
	}
}

// Start starts the DoH server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoH)

	server := &http.Server{
		Addr:    s.Addr,
		Handler: mux,
	}

	// Enable HTTP/2
	if err := http2.ConfigureServer(server, nil); err != nil {
		return fmt.Errorf("failed to configure http2: %v", err)
	}

	log.Printf("Starting DoH Server on %s (Upstream: %s)", s.Addr, s.UpstreamTarget)
	if err := server.ListenAndServeTLS(s.CertFile, s.KeyFile); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// handleDoH handles RFC 8484 DNS queries.
func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var msgBytes []byte
	var err error

	switch r.Method {
	case http.MethodPost:
		if r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		msgBytes, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing 'dns' query parameter", http.StatusBadRequest)
			return
		}
		msgBytes, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid Base64", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Unpack DNS message
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(msgBytes); err != nil {
		http.Error(w, "Malformed DNS message", http.StatusBadRequest)
		return
	}

	// Record request stats
	if s.Metrics != nil && len(reqMsg.Question) > 0 {
		qName := reqMsg.Question[0].Name
		qType := dns.TypeToString[reqMsg.Question[0].Qtype]
		s.Metrics.IncrementQueries(qName)
		s.Metrics.RecordQueryType(qType)
	}

	// Execute Plugins
	if s.PM != nil {
		dohWriter := &DoHResponseWriter{w: w, r: r}
		ctx := &plugins.PluginContext{
			ResponseWriter: dohWriter,
			Metrics:        s.Metrics,
		}
		if handled := s.PM.ExecutePlugins(ctx, dohWriter, reqMsg); handled {
			return // Plugin handled request (e.g. blocked)
		}
	}

	startTime := time.Now()
	// Forward to Upstream (Knot Resolver)
	respMsg, _, err := s.Client.Exchange(reqMsg, s.UpstreamTarget)
	if err != nil {
		log.Printf("DoH Upstream Error: %v", err)
		http.Error(w, "DNS Upstream Error", http.StatusBadGateway)
		return
	}

	// Record response stats
	if s.Metrics != nil && len(reqMsg.Question) > 0 {
		latency := time.Since(startTime)
		qName := reqMsg.Question[0].Name
		s.Metrics.RecordLatency(qName, latency)
		s.Metrics.RecordResponseCode(dns.RcodeToString[respMsg.Rcode])
		if respMsg.Rcode == dns.RcodeNameError {
			s.Metrics.RecordNXDOMAIN(qName)
		}
	}

	// Pack response
	packedResp, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(packedResp)
}

// DoHResponseWriter adapts http.ResponseWriter to dns.ResponseWriter interface
type DoHResponseWriter struct {
	w http.ResponseWriter
	r *http.Request
}

func (d *DoHResponseWriter) LocalAddr() net.Addr {
	// Dummy local addr
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func (d *DoHResponseWriter) RemoteAddr() net.Addr {
	host, port, _ := net.SplitHostPort(d.r.RemoteAddr)
	p, _ := net.LookupPort("tcp", port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

func (d *DoHResponseWriter) WriteMsg(msg *dns.Msg) error {
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	d.w.Header().Set("Content-Type", "application/dns-message")
	d.w.WriteHeader(http.StatusOK)
	_, err = d.w.Write(packed)
	return err
}

func (d *DoHResponseWriter) Write(b []byte) (int, error) {
	return d.w.Write(b)
}

func (d *DoHResponseWriter) Close() error {
	return nil
}

func (d *DoHResponseWriter) TsigStatus() error {
	return nil
}

func (d *DoHResponseWriter) TsigTimersOnly(bool) {
}

func (d *DoHResponseWriter) Hijack() {
}
