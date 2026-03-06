package odoh

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"

	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// Server represents an Oblivious DNS-over-HTTPS server.
type Server struct {
	Addr           string
	TLSConfig      *tls.Config
	UpstreamTarget string
	Client         *dns.Client
	PM             *plugins.PluginManager
	Metrics        *metrics.Metrics

	// ODoH specific
	KeyPair odoh.ObliviousDoHKeyPair
}

// NewServer creates a new ODoH server.
func NewServer(addr string, tlsConfig *tls.Config, upstream string, pm *plugins.PluginManager, m *metrics.Metrics) (*Server, error) {
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
		KeyPair:        kp,
		Client: &dns.Client{
			Net:     "udp",
			Timeout: 2 * time.Second,
		},
	}, nil
}

// Start starts the ODoH server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleODoH)
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

	log.Printf("Starting ODoH Server on %s (Upstream: %s)", s.Addr, s.UpstreamTarget)

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

func (s *Server) handleODoH(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	outcome := "resolved"
	rcodeText := "UNKNOWN"

	if s.Metrics != nil {
		s.Metrics.IncrementInflightRequests()
		defer s.Metrics.DecrementInflightRequests()
		defer s.Metrics.RecordRequestOutcome("odoh", outcome, rcodeText, time.Since(requestStart))
	}

	if r.Method != http.MethodPost {
		outcome = "malformed_http"
		if s.Metrics != nil {
			s.Metrics.RecordMalformedRequest("odoh")
		}
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != "application/oblivious-dns-message" {
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
	rcodeText = dns.RcodeToString[dns.RcodeSuccess]

	// --- Existing Logic (Metrics, Plugins, Resolution) ---

	// Record request stats
	if s.Metrics != nil {
		qName := reqMsg.Question[0].Name
		qType := dns.TypeToString[reqMsg.Question[0].Qtype]
		s.Metrics.IncrementQueries(qName)
		s.Metrics.RecordQueryType(qType)
	}

	dummyWriter := &DumbResponseWriter{}

	// Execute Plugins
	if s.PM != nil {
		ctx := &plugins.PluginContext{
			ResponseWriter: dummyWriter, // This won't work perfectly if plugin writes to writer directly and stops.
			Metrics:        s.Metrics,
		}
		if handled := s.PM.ExecutePlugins(ctx, dummyWriter, reqMsg); handled {
			if dummyWriter.Msg != nil {
				outcome = "plugin_handled"
				rcodeText = dns.RcodeToString[dummyWriter.Msg.Rcode]
				s.sendEncryptedResponse(w, responseContext, dummyWriter.Msg)
				return
			}
		}
	}

	startTime := time.Now()
	// Forward to Upstream
	respMsg, _, err := s.Client.Exchange(reqMsg, s.UpstreamTarget)
	if err != nil {
		log.Printf("ODoH Upstream Error: %v", err)
		outcome = "resolver_error"
		rcodeText = dns.RcodeToString[dns.RcodeServerFailure]
		if s.Metrics != nil {
			s.Metrics.IncrementUnboundErrors()
		}
		http.Error(w, "DNS Upstream Error", http.StatusBadGateway)
		return
	}
	rcodeText = dns.RcodeToString[respMsg.Rcode]

	// Record response stats
	if s.Metrics != nil {
		latency := time.Since(startTime)
		qName := reqMsg.Question[0].Name
		s.Metrics.RecordLatency(qName, latency)
		s.Metrics.RecordResponseCode(dns.RcodeToString[respMsg.Rcode])
		if respMsg.Rcode == dns.RcodeNameError {
			s.Metrics.RecordNXDOMAIN(qName)
		}
	}

	s.sendEncryptedResponse(w, responseContext, respMsg)
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
