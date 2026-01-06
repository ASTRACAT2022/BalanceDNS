package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/pool"
	"dns-resolver/internal/resolver"

	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

// Server holds the server state.
type Server struct {
	config        *config.Config
	handler       dns.Handler
	metrics       *metrics.Metrics
	resolver      resolver.ResolverInterface
	pluginManager *plugins.PluginManager
	odohKeyPair   odoh.ObliviousDoHKeyPair
	odohConfigs   odoh.ObliviousDoHConfigs
}

// NewServer creates a new server.
func NewServer(cfg *config.Config, m *metrics.Metrics, res resolver.ResolverInterface, pm *plugins.PluginManager) *Server {
	// Initialize ODoH keys
	kp, err := odoh.CreateDefaultKeyPair()
	if err != nil {
		log.Printf("Failed to generate ODoH keypair: %v", err)
	}
	configs := odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{kp.Config})

	s := &Server{
		config:        cfg,
		metrics:       m,
		resolver:      res,
		pluginManager: pm,
		odohKeyPair:   kp,
		odohConfigs:   configs,
	}
	s.buildAndSetHandler()
	return s
}

func (s *Server) buildAndSetHandler() {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) > 0 {
			s.metrics.RecordQueryType(dns.TypeToString[r.Question[0].Qtype])
		}

		// Execute request plugins
		pluginCtx := &plugins.PluginContext{ResponseWriter: w, Metrics: s.metrics}
		if s.pluginManager.ExecutePlugins(pluginCtx, w, r) {
			// A plugin has already handled the request.
			// The plugin is responsible for writing the response.
			return
		}

		req := pool.GetDnsMsg()
		defer pool.PutDnsMsg(req)

		req.SetQuestion(r.Question[0].Name, r.Question[0].Qtype)
		req.RecursionDesired = true
		req.SetEdns0(4096, true)

		ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
		defer cancel()

		msg, err := s.resolver.Resolve(ctx, req)
		if err != nil {
			log.Printf("Failed to resolve %s: %v", req.Question[0].Name, err)
			s.metrics.RecordResponseCode(dns.RcodeToString[dns.RcodeServerFailure])
			dns.HandleFailed(w, r)
			return
		}

		s.metrics.RecordResponseCode(dns.RcodeToString[msg.Rcode])
		msg.Id = r.Id

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to write response: %v", err)
		}
	})
	s.handler = s.metricsWrapper(handler)
}

// ListenAndServe starts the DNS server.
func (s *Server) ListenAndServe() {
	go s.startListener("udp")
	go s.startListener("tcp")

	// Start DoT if certs are provided
	if s.config.CertFile != "" && s.config.KeyFile != "" {
		go s.startListener("tcp-tls")
	} else if s.config.DoTAddr != "" {
		log.Println("DoT address configured but no cert/key provided. Skipping DoT.")
	}

	// Start DoH/ODoH if certs are provided
	if s.config.CertFile != "" && s.config.KeyFile != "" {
		go s.startDoHListener()
	} else if s.config.DoHAddr != "" {
		log.Println("DoH address configured but no cert/key provided. Skipping DoH.")
	}

	log.Printf("ASTRACAT DNS Resolver is running on %s", s.config.ListenAddr)
	select {} // Block forever
}

func (s *Server) startDoHListener() {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.handleDoHRequest)
	mux.HandleFunc("/odohconfigs", s.handleODoHConfigs)

	srv := &http.Server{
		Addr:    s.config.DoHAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Starting DoH/ODoH listener on %s", s.config.DoHAddr)
	if err := srv.ListenAndServeTLS(s.config.CertFile, s.config.KeyFile); err != nil {
		log.Printf("Failed to start DoH listener: %v", err)
	}
}

func (s *Server) handleODoHConfigs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/oblivious-doh-configs")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.Write(s.odohConfigs.Marshal())
}

func (s *Server) handleDoHRequest(w http.ResponseWriter, r *http.Request) {
	// Check for ODoH Content Type
	if r.Header.Get("Content-Type") == "application/oblivious-dns-message" {
		s.handleODoHRequest(w, r)
		return
	}

	if r.Method != "POST" && r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg *dns.Msg

	if r.Method == "GET" {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}

		decoded, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid base64 parameter", http.StatusBadRequest)
			return
		}

		msg = new(dns.Msg)
		if err := msg.Unpack(decoded); err != nil {
			http.Error(w, "Invalid DNS message", http.StatusBadRequest)
			return
		}
	} else {
		// POST: read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			http.Error(w, "Invalid DNS message", http.StatusBadRequest)
			return
		}
	}

	// Use the existing DNS handler logic via a ResponseWriter adapter
	// We need a custom ResponseWriter to capture the response and write it to HTTP
	dw := &dohResponseWriter{w: w}
	s.handler.ServeDNS(dw, msg)
}

func (s *Server) handleODoHRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "ODoH requires POST", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// 1. Unmarshal ODoH Encrypted Message
	odohMsg, err := odoh.UnmarshalDNSMessage(body)
	if err != nil {
		log.Printf("ODoH Unmarshal Error: %v", err)
		http.Error(w, "Invalid ODoH message", http.StatusBadRequest)
		return
	}

	// 2. Decrypt Query
	query, responseContext, err := s.odohKeyPair.DecryptQuery(odohMsg)
	if err != nil {
		log.Printf("ODoH Decrypt Error: %v", err)
		http.Error(w, "Failed to decrypt query", http.StatusBadRequest)
		return
	}

	// 3. Resolve DNS (Plain DNS)
	dnsReq := new(dns.Msg)
	if err := dnsReq.Unpack(query.Message()); err != nil {
		log.Printf("ODoH Inner DNS Unpack Error: %v", err)
		http.Error(w, "Invalid inner DNS message", http.StatusBadRequest)
		return
	}

	// Capture response
	dw := &odohResponseWriter{}
	s.handler.ServeDNS(dw, dnsReq)

	if dw.msg == nil {
		http.Error(w, "Resolution failed", http.StatusInternalServerError)
		return
	}

	packedResp, err := dw.msg.Pack()
	if err != nil {
		http.Error(w, "Pack error", http.StatusInternalServerError)
		return
	}

	// 4. Encrypt Response
	obliviousResp := odoh.CreateObliviousDNSResponse(packedResp, 0)
	encryptedResp, err := responseContext.EncryptResponse(obliviousResp)
	if err != nil {
		log.Printf("ODoH Encrypt Error: %v", err)
		http.Error(w, "Failed to encrypt response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/oblivious-dns-message")
	w.Write(encryptedResp.Marshal())
}

// dohResponseWriter adapts http.ResponseWriter to dns.ResponseWriter
type dohResponseWriter struct {
	w http.ResponseWriter
}

func (d *dohResponseWriter) LocalAddr() net.Addr  { return nil }
func (d *dohResponseWriter) RemoteAddr() net.Addr { return nil }
func (d *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	packed, err := msg.Pack()
	if err != nil {
		return err
	}
	d.w.Header().Set("Content-Type", "application/dns-message")
	d.w.Write(packed)
	return nil
}
func (d *dohResponseWriter) Write(b []byte) (int, error) { return d.w.Write(b) }
func (d *dohResponseWriter) Close() error                { return nil }
func (d *dohResponseWriter) TsigStatus() error           { return nil }
func (d *dohResponseWriter) TsigTimersOnly(bool)         {}
func (d *dohResponseWriter) Hijack()                     {}

// odohResponseWriter captures the DNS message for ODoH encryption
type odohResponseWriter struct {
	msg *dns.Msg
}

func (d *odohResponseWriter) LocalAddr() net.Addr  { return nil }
func (d *odohResponseWriter) RemoteAddr() net.Addr { return nil }
func (d *odohResponseWriter) WriteMsg(msg *dns.Msg) error {
	d.msg = msg
	return nil
}
func (d *odohResponseWriter) Write(b []byte) (int, error) { return 0, nil }
func (d *odohResponseWriter) Close() error                { return nil }
func (d *odohResponseWriter) TsigStatus() error           { return nil }
func (d *odohResponseWriter) TsigTimersOnly(bool)         {}
func (d *odohResponseWriter) Hijack()                     {}

func (s *Server) startListener(net string) {
	var addr string
	switch net {
	case "tcp-tls":
		addr = s.config.DoTAddr
	default:
		addr = s.config.ListenAddr
	}

	server := &dns.Server{Addr: addr, Net: net, Handler: s.handler}
	if net == "tcp-tls" {
		cert, err := tls.LoadX509KeyPair(s.config.CertFile, s.config.KeyFile)
		if err != nil {
			log.Printf("Failed to load TLS certs for DoT: %v", err)
			return
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	log.Printf("Starting %s listener on %s", net, addr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to start %s listener: %s", net, err)
	}
}

// metricsWrapper is a middleware that increments the query counter.
func (s *Server) metricsWrapper(h dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		domain := ""
		if len(r.Question) > 0 {
			domain = r.Question[0].Name
		}
		s.metrics.IncrementQueries(domain)
		h.ServeDNS(w, r)
	})
}
