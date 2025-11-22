package server

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/pool"
	"dns-resolver/internal/resolver"
	"github.com/miekg/dns"
)

// Server holds the server state.
type Server struct {
	config        *config.Config
	handler       dns.Handler
	metrics       *metrics.Metrics
	resolver      resolver.ResolverInterface
	pluginManager *plugins.PluginManager
}

// NewServer creates a new server.
func NewServer(cfg *config.Config, m *metrics.Metrics, res resolver.ResolverInterface, pm *plugins.PluginManager) *Server {
	s := &Server{
		config:        cfg,
		metrics:       m,
		resolver:      res,
		pluginManager: pm,
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

		ctx, cancel := context.WithTimeout(context.Background(), s.config.Resolver.RequestTimeout)
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
	go s.startListener("udp", s.config.ListenAddr)
	go s.startListener("tcp", s.config.ListenAddr)

	if s.config.DoT.Enabled {
		go s.startTlsListener("tcp-tls", s.config.DoT.ListenAddr, s.config.DoT.CertFile, s.config.DoT.KeyFile)
	}

	if s.config.DoH.Enabled {
		go s.startDoHListener()
	}

	log.Printf("ASTRACAT DNS Resolver is running on %s", s.config.ListenAddr)
	select {} // Block forever
}

func (s *Server) startDoHListener() {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.dohHandler)

	httpServer := &http.Server{
		Addr:    s.config.DoH.ListenAddr,
		Handler: mux,
	}

	log.Printf("Starting DoH listener on %s", s.config.DoH.ListenAddr)
	if err := httpServer.ListenAndServeTLS(s.config.DoH.CertFile, s.config.DoH.KeyFile); err != nil {
		log.Printf("Failed to start DoH listener: %s", err)
	}
}

func (s *Server) startListener(net, addr string) {
	server := &dns.Server{Addr: addr, Net: net, Handler: s.handler}
	log.Printf("Starting %s listener on %s", net, addr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to start %s listener: %s", net, err)
	}
}

func (s *Server) startTlsListener(net, addr, certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("Failed to load TLS key pair for %s: %v", net, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server := &dns.Server{
		Addr:      addr,
		Net:       net,
		Handler:   s.handler,
		TLSConfig: tlsConfig,
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
