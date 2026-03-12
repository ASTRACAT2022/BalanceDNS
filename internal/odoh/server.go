package odoh

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

var errUnsupportedDoHMediaType = errors.New("unsupported DoH media type")

// Server represents an Oblivious DNS-over-HTTPS server.
type Server struct {
	Addr           string
	TLSConfig      *tls.Config
	UpstreamTarget string
	Client         *dns.Client
	PM             *plugins.PluginManager
	Metrics        *metrics.Metrics
	DropANYQueries bool

	// ODoH specific
	KeyPair odoh.ObliviousDoHKeyPair
}

// NewServer creates a new ODoH server.
func NewServer(addr string, tlsConfig *tls.Config, upstream string, pm *plugins.PluginManager, m *metrics.Metrics, dropANYQueries bool) (*Server, error) {
	if tlsConfig == nil {
		return nil, fmt.Errorf("tls config is nil")
	}

	// Generate a key pair for ODoH (HPKE)
	// Using default suite (P256 or similar depending on library default)
	kp, err := odoh.CreateDefaultKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to create ODoH key pair: %v", err)
	}

	return &Server{
		Addr:           addr,
		TLSConfig:      tlsConfig,
		UpstreamTarget: upstream,
		PM:             pm,
		Metrics:        m,
		DropANYQueries: dropANYQueries,
		KeyPair:        kp,
		Client: &dns.Client{
			Net:     "udp",
			Timeout: 3 * time.Second,
			UDPSize: 1232,
		},
	}, nil
}

// Start starts the combined DoH/ODoH server.
func (s *Server) Start() error {
	if s.TLSConfig == nil {
		return fmt.Errorf("tls config is nil")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDNSQuery)
	mux.HandleFunc("/odohconfigs", s.handleODoHConfigs)

	server := &http.Server{
		Addr:              s.Addr,
		Handler:           mux,
		TLSConfig:         s.TLSConfig,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Enable HTTP/2
	if err := http2.ConfigureServer(server, nil); err != nil {
		return fmt.Errorf("failed to configure http2: %v", err)
	}

	log.Printf("Starting DoH/ODoH Server on %s (Upstream: %s)", s.Addr, s.UpstreamTarget)

	// Print the public key config
	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{s.KeyPair.Config})
	packedConfigs := configs.Marshal()
	log.Printf("ODoH Configs (Base64Url): %s", hex.EncodeToString(packedConfigs))

	// Create TLS listener using our config
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	tlsListener := tls.NewListener(ln, s.TLSConfig)
	if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	// ODoH request uses application/oblivious-dns-message over POST.
	if r.Method == http.MethodPost && isODoHContentType(r.Header.Get("Content-Type")) {
		s.handleODoH(w, r)
		return
	}
	// Everything else on /dns-query is treated as standard DoH.
	s.handleDoH(w, r)
}

func (s *Server) handleODoHConfigs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{s.KeyPair.Config})
	packedConfigs := configs.Marshal()

	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(packedConfigs)
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	outcome := "resolved"
	rcodeText := "UNKNOWN"

	if s.Metrics != nil {
		s.Metrics.IncrementInflightRequests()
		defer s.Metrics.DecrementInflightRequests()
		defer func() {
			s.Metrics.RecordRequestOutcome("doh", outcome, rcodeText, time.Since(requestStart))
		}()
	}

	reqMsg, err := parseDoHRequest(r)
	if err != nil {
		outcome = "malformed_http"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("doh")
		}
		if errors.Is(err, errUnsupportedDoHMediaType) {
			http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
			return
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	respMsg, resolveOutcome, err := s.resolveDNSMessage(r.Context(), "doh", reqMsg)
	if err != nil {
		log.Printf("DoH Upstream Error: %v", err)
		outcome = resolveOutcome
		rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
		http.Error(w, "DNS Upstream Error", http.StatusBadGateway)
		return
	}

	outcome = resolveOutcome
	rcodeText = dns.RcodeToString[respMsg.Rcode]
	wire, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(wire)
}

func (s *Server) handleODoH(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	outcome := "resolved"
	rcodeText := "UNKNOWN"

	if s.Metrics != nil {
		s.Metrics.IncrementInflightRequests()
		defer s.Metrics.DecrementInflightRequests()
		defer func() {
			s.Metrics.RecordRequestOutcome("odoh", outcome, rcodeText, time.Since(requestStart))
		}()
	}

	if r.Method != http.MethodPost {
		outcome = "malformed_http"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !isODoHContentType(r.Header.Get("Content-Type")) {
		outcome = "malformed_http"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		outcome = "malformed_http"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Parse ODoH Message
	odohMsg, err := odoh.UnmarshalDNSMessage(bodyBytes)
	if err != nil {
		log.Printf("ODoH Parse Error: %v", err)
		outcome = "decrypt_error"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Decrypt the query
	query, responseContext, err := s.KeyPair.DecryptQuery(odohMsg)
	if err != nil {
		log.Printf("ODoH Decrypt Error: %v", err)
		outcome = "decrypt_error"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Decryption Failed", http.StatusBadRequest)
		return
	}

	// Unpack inner DNS message
	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(query.DnsMessage); err != nil {
		log.Printf("Failed to unpack inner DNS message: %v", err)
		outcome = "malformed_dns"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Malformed DNS message", http.StatusBadRequest)
		return
	}
	if len(reqMsg.Question) == 0 {
		outcome = "malformed_dns"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Malformed DNS message", http.StatusBadRequest)
		return
	}

	respMsg, resolveOutcome, err := s.resolveDNSMessage(r.Context(), "odoh", reqMsg)
	if err != nil {
		log.Printf("ODoH Upstream Error: %v", err)
		outcome = resolveOutcome
		rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
		http.Error(w, "DNS Upstream Error", http.StatusBadGateway)
		return
	}

	outcome = resolveOutcome
	rcodeText = dns.RcodeToString[respMsg.Rcode]
	s.sendEncryptedResponse(w, responseContext, respMsg)
}

func parseDoHRequest(r *http.Request) (*dns.Msg, error) {
	switch r.Method {
	case http.MethodGet:
		return parseDoHGETRequest(r)
	case http.MethodPost:
		return parseDoHPOSTRequest(r)
	default:
		return nil, fmt.Errorf("method not allowed: %s", r.Method)
	}
}

func parseDoHGETRequest(r *http.Request) (*dns.Msg, error) {
	wireParam := r.URL.Query().Get("dns")
	if wireParam == "" {
		return nil, errors.New("missing dns query parameter")
	}
	wire, err := base64.RawURLEncoding.DecodeString(wireParam)
	if err != nil {
		// Some clients include padding; accept it as well.
		wire, err = base64.URLEncoding.DecodeString(wireParam)
		if err != nil {
			return nil, fmt.Errorf("invalid dns query parameter: %w", err)
		}
	}
	return unpackDNSMessage(wire)
}

func parseDoHPOSTRequest(r *http.Request) (*dns.Msg, error) {
	contentType := normalizeContentType(r.Header.Get("Content-Type"))
	if contentType != "" && contentType != "application/dns-message" {
		return nil, errUnsupportedDoHMediaType
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	return unpackDNSMessage(body)
}

func unpackDNSMessage(wire []byte) (*dns.Msg, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}
	if len(msg.Question) == 0 {
		return nil, errors.New("dns message has no question")
	}
	return msg, nil
}

func isODoHContentType(contentType string) bool {
	return normalizeContentType(contentType) == "application/oblivious-dns-message"
}

func normalizeContentType(contentType string) string {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if contentType == "" {
		return ""
	}
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	return contentType
}

func (s *Server) resolveDNSMessage(ctx context.Context, transport string, reqMsg *dns.Msg) (*dns.Msg, string, error) {
	if len(reqMsg.Question) == 0 {
		return nil, "malformed_dns", errors.New("dns message has no question")
	}

	question := reqMsg.Question[0]
	if s.Metrics != nil {
		s.Metrics.RecordDNSQuery(question)
	}

	if s.DropANYQueries && question.Qtype == dns.TypeANY {
		if s.Metrics != nil {
			s.Metrics.RecordSecurityDrop("any_query", transport)
			s.Metrics.RecordDNSResponse(question.Name, dns.RcodeRefused)
		}
		refused := new(dns.Msg)
		refused.SetRcode(reqMsg, dns.RcodeRefused)
		return refused, "security_drop_any_query", nil
	}

	dummyWriter := &DumbResponseWriter{}
	if s.PM != nil {
		ctx := &plugins.PluginContext{
			ResponseWriter: dummyWriter,
			Metrics:        s.Metrics,
		}
		if handled := s.PM.ExecutePlugins(ctx, dummyWriter, reqMsg); handled {
			if dummyWriter.Msg != nil {
				s.recordResponseCodeMetrics(question.Name, dummyWriter.Msg.Rcode)
				return dummyWriter.Msg, "plugin_handled", nil
			}
			if question.Qtype == dns.TypeANY && s.Metrics != nil {
				s.Metrics.RecordSecurityDrop("any_query", transport)
			}
			// HTTP-based DNS transport cannot silently drop; synthesize REFUSED.
			refused := new(dns.Msg)
			refused.SetRcode(reqMsg, dns.RcodeRefused)
			s.recordResponseCodeMetrics(question.Name, refused.Rcode)
			if question.Qtype == dns.TypeANY {
				return refused, "security_drop_any_query", nil
			}
			return refused, "plugin_dropped", nil
		}
	}

	ensureEDNS(reqMsg)

	startTime := time.Now()
	respMsg, err := s.exchangeUpstream(ctx, reqMsg)
	if err != nil {
		if s.Metrics != nil {
			s.Metrics.IncrementUnboundErrors()
		}
		return nil, "resolver_error", err
	}

	if s.Metrics != nil {
		s.Metrics.RecordLatency(question.Name, time.Since(startTime))
	}
	s.recordResponseCodeMetrics(question.Name, respMsg.Rcode)
	return respMsg, "resolved", nil
}

func (s *Server) exchangeUpstream(ctx context.Context, reqMsg *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	udpClient := s.Client
	if udpClient == nil {
		udpClient = &dns.Client{Net: "udp", Timeout: 3 * time.Second, UDPSize: 1232}
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		respMsg, _, err := udpClient.ExchangeContext(ctx, reqMsg.Copy(), s.UpstreamTarget)
		if err == nil {
			if respMsg != nil && respMsg.Truncated {
				return s.exchangeUpstreamTCP(ctx, reqMsg)
			}
			return respMsg, nil
		}
		lastErr = err
		if !isRetriableUpstreamError(err) {
			break
		}
	}

	// Fallback to TCP for truncation/overflow and for transient UDP timeouts.
	if shouldFallbackTCPOnUpstreamError(lastErr) || isRetriableUpstreamError(lastErr) {
		return s.exchangeUpstreamTCP(ctx, reqMsg)
	}
	return nil, lastErr
}

func (s *Server) exchangeUpstreamTCP(ctx context.Context, reqMsg *dns.Msg) (*dns.Msg, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	tcpClient := &dns.Client{Net: "tcp", Timeout: 4 * time.Second}
	respMsg, _, err := tcpClient.ExchangeContext(ctx, reqMsg.Copy(), s.UpstreamTarget)
	if err != nil {
		return nil, err
	}
	return respMsg, nil
}

func ensureEDNS(msg *dns.Msg) {
	if msg == nil {
		return
	}
	if msg.IsEdns0() == nil {
		msg.SetEdns0(1232, true)
	}
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

func (s *Server) recordResponseCodeMetrics(qName string, rcode int) {
	if s.Metrics == nil {
		return
	}
	s.Metrics.RecordResponseCode(dns.RcodeToString[rcode])
	if rcode == dns.RcodeNameError {
		s.Metrics.RecordNXDOMAIN(qName)
	}
}

func (s *Server) sendEncryptedResponse(w http.ResponseWriter, ctx odoh.ResponseContext, answer *dns.Msg) {
	packedAnswer, err := answer.Pack()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Create ODoH Response
	odohResp := odoh.CreateObliviousDNSResponse(packedAnswer, 0) // 0 padding

	// Encrypt the response
	encAnswer, err := ctx.EncryptResponse(odohResp)
	if err != nil {
		log.Printf("ODoH Encryption Error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	respBytes := encAnswer.Marshal()

	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// DumbResponseWriter captures the DNS response for plugins
type DumbResponseWriter struct {
	Msg *dns.Msg
}

func (d *DumbResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}
func (d *DumbResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}
func (d *DumbResponseWriter) WriteMsg(msg *dns.Msg) error {
	d.Msg = msg
	return nil
}
func (d *DumbResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *DumbResponseWriter) Close() error                { return nil }
func (d *DumbResponseWriter) TsigStatus() error           { return nil }
func (d *DumbResponseWriter) TsigTimersOnly(bool)         {}
func (d *DumbResponseWriter) Hijack()                     {}
