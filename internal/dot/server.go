package dot

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"strings"
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
			Net:     "udp",
			Timeout: 3 * time.Second,
			UDPSize: 1232,
		},
	}
}

// Start starts the DoT server.
func (s *Server) Start() error {
	log.Printf("Starting DoT Server on %s (Upstream: %s)", s.Addr, s.UpstreamTarget)

	srv := &dns.Server{
		Addr:         s.Addr,
		Net:          "tcp-tls",
		TLSConfig:    s.TLSConfig,
		Handler:      dns.HandlerFunc(s.handleRequest),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  func() time.Duration { return 30 * time.Second },
	}

	return srv.ListenAndServe()
}

// handleRequest handles incoming DoT queries.
func (s *Server) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	requestStart := time.Now()
	outcome := "resolved"
	rcodeText := dns.RcodeToString[dns.RcodeSuccess]

	if s.Metrics != nil {
		s.Metrics.IncrementInflightRequests()
		defer s.Metrics.DecrementInflightRequests()
		defer s.Metrics.RecordRequestOutcome("dot", outcome, rcodeText, time.Since(requestStart))
	}

	if r == nil || len(r.Question) == 0 {
		outcome = "malformed"
		rcodeText = dns.RcodeToString[dns.RcodeFormatError]
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("dot")
		}
		m := new(dns.Msg)
		if r != nil {
			m.SetRcode(r, dns.RcodeFormatError)
		} else {
			m.MsgHdr.Response = true
			m.Rcode = dns.RcodeFormatError
		}
		_ = w.WriteMsg(m)
		return
	}

	// 1. Record Request Metrics
	if s.Metrics != nil {
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
			outcome = "plugin_handled"
			return // Plugin handled (e.g. blocked)
		}
	}

	// 3. Forward to Upstream
	// DoT is TCP-based, so we likely want to forward via TCP or UDP.
	// Since upstream is local Knot (optimised), UDP is fine, but TCP handles large responses better.
	// We'll trust the client config (default TCP).

	resolveStart := time.Now()
	upstreamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := s.exchangeUpstream(upstreamCtx, r)
	if err != nil {
		log.Printf("DoT Upstream Error: %v", err)
		outcome = "resolver_error"
		rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
		if s.Metrics != nil {
			s.Metrics.IncrementUnboundErrors()
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	rcodeText = dns.RcodeToString[resp.Rcode]

	// 4. Record Response Metrics
	if s.Metrics != nil {
		latency := time.Since(resolveStart)
		qName := r.Question[0].Name
		s.Metrics.RecordLatency(qName, latency)
		s.Metrics.RecordResponseCode(dns.RcodeToString[resp.Rcode])
		if resp.Rcode == dns.RcodeNameError {
			s.Metrics.RecordNXDOMAIN(qName)
		}
	}

	_ = w.WriteMsg(resp)
}

func (s *Server) exchangeUpstream(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	udpClient := s.Client
	if udpClient == nil {
		udpClient = &dns.Client{Net: "udp", Timeout: 3 * time.Second, UDPSize: 1232}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, _, err := udpClient.ExchangeContext(ctx, req.Copy(), s.UpstreamTarget)
		if err == nil {
			if resp != nil && resp.Truncated {
				return s.exchangeUpstreamTCP(ctx, req)
			}
			return resp, nil
		}
		lastErr = err
		if !isRetriableUpstreamError(err) {
			break
		}
	}

	if shouldFallbackTCPOnUpstreamError(lastErr) || isRetriableUpstreamError(lastErr) {
		return s.exchangeUpstreamTCP(ctx, req)
	}
	return nil, lastErr
}

func (s *Server) exchangeUpstreamTCP(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	tcpClient := &dns.Client{Net: "tcp", Timeout: 4 * time.Second}
	resp, _, err := tcpClient.ExchangeContext(ctx, req.Copy(), s.UpstreamTarget)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func isRetriableUpstreamError(err error) bool {
	if err == nil {
		return false
	}
	if nerr, ok := err.(net.Error); ok {
		return nerr.Timeout() || nerr.Temporary()
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "temporary")
}

func shouldFallbackTCPOnUpstreamError(err error) bool {
	if err == nil {
		return false
	}
	if nerr, ok := err.(net.Error); ok {
		if nerr.Timeout() || nerr.Temporary() {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "buffer size too small") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "temporary") ||
		strings.Contains(msg, "overflow") ||
		strings.Contains(msg, "truncated")
}
