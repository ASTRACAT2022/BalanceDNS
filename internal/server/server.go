package server

import (
	"context"
	"log"
	"net"
	"sync"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/internal/resolver"
	"github.com/miekg/dns"
)

var msgPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Msg)
	},
}

var responseWriterPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

// Server holds the server state.
type Server struct {
	config        *config.Config
	handler       dns.Handler
	metrics       *metrics.Metrics
	resolver      resolver.ResolverInterface
	pluginManager *plugins.PluginManager
	rateLimiter   *RateLimiter
}

// NewServer creates a new server.
func NewServer(cfg *config.Config, m *metrics.Metrics, res resolver.ResolverInterface, pm *plugins.PluginManager) *Server {
	s := &Server{
		config:        cfg,
		metrics:       m,
		resolver:      res,
		pluginManager: pm,
		rateLimiter:   NewRateLimiter(100, 200), // 100 requests per second, burst of 200
	}
	s.buildAndSetHandler()
	return s
}

func (s *Server) buildAndSetHandler() {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// Get the client IP for rate limiting
		clientIP := getClientIP(w)
		
		// Apply rate limiting
		if !s.rateLimiter.Allow(clientIP) {
			log.Printf("Rate limit exceeded for client: %s", clientIP)
			s.metrics.IncrementRateLimitExceeded()
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused) // REFUSED for rate-limited requests
			w.WriteMsg(m)
			return
		}

		// Record query type
		if len(r.Question) > 0 {
			s.metrics.RecordQueryType(dns.TypeToString[r.Question[0].Qtype])
		}

		// Execute request plugins
		pluginCtx := &plugins.PluginContext{}
		s.pluginManager.ExecutePlugins(pluginCtx, r)

		// Use pooled request object
		req := msgPool.Get().(*dns.Msg)
		defer func() {
			*req = dns.Msg{}
			msgPool.Put(req)
		}()

		// Copy question and settings from the original request
		req.SetQuestion(r.Question[0].Name, r.Question[0].Qtype)
		req.RecursionDesired = true
		if opt := r.IsEdns0(); opt != nil {
			req.SetEdns0(opt.UDPSize(), opt.Do())
		} else {
			req.SetEdns0(4096, true)
		}

		// Use a context with the request timeout from config
		ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
		defer cancel()

		// Resolve the query using the resolver
		msg, err := s.resolver.Resolve(ctx, req)
		if err != nil {
			log.Printf("Failed to resolve %s: %v", req.Question[0].Name, err)
			s.metrics.RecordResponseCode(dns.RcodeToString[dns.RcodeServerFailure])
			
			// Create appropriate error response
			errorMsg := new(dns.Msg)
			errorMsg.SetRcode(r, dns.RcodeServerFailure)
			errorMsg.Id = r.Id
			if err := w.WriteMsg(errorMsg); err != nil {
				s.metrics.IncrementResponseWriteErrors()
				log.Printf("Failed to write error response: %v", err)
			}
			return
		}

		s.metrics.RecordResponseCode(dns.RcodeToString[msg.Rcode])
		msg.Id = r.Id

		// Write the response
		if err := w.WriteMsg(msg); err != nil {
			s.metrics.IncrementResponseWriteErrors()
			log.Printf("Failed to write response: %v", err)
			
			// Try to send a failure response if the original write failed
			errorMsg := new(dns.Msg)
			errorMsg.SetRcode(r, dns.RcodeServerFailure)
			errorMsg.Id = r.Id
			if err2 := w.WriteMsg(errorMsg); err2 != nil {
				log.Printf("Failed to write fallback error response: %v", err2)
			}
		}
	})
	s.handler = s.metricsWrapper(handler)
}

// getClientIP extracts the client IP from the response writer
func getClientIP(w dns.ResponseWriter) string {
	if tcpConn, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		return tcpConn.IP.String()
	}
	if udpConn, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		return udpConn.IP.String()
	}
	return w.RemoteAddr().String()
}

// ListenAndServe starts the DNS server.
func (s *Server) ListenAndServe() {
	// Configure DNS server with optimized settings
	udpServer := &dns.Server{
		Addr:    s.config.ListenAddr,
		Net:     "udp",
		Handler: s.handler,
		UDPSize: 65535,
		// Enable proper connection reuse and optimization
		ReusePort: true,
	}
	
	tcpServer := &dns.Server{
		Addr:    s.config.ListenAddr,
		Net:     "tcp",
		Handler: s.handler,
		// Enable proper connection reuse and optimization
		ReusePort: true,
	}

	// Start listeners in separate goroutines
	go func() {
		log.Printf("Starting UDP listener on %s", s.config.ListenAddr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP listener: %s", err)
		}
	}()

	go func() {
		log.Printf("Starting TCP listener on %s", s.config.ListenAddr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP listener: %s", err)
		}
	}()

	log.Printf("ASTRACAT DNS Resolver is running on %s", s.config.ListenAddr)
	select {} // Block forever
}

// metricsWrapper is a middleware that increments the query counter.
func (s *Server) metricsWrapper(h dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.metrics.IncrementQueries()
		h.ServeDNS(w, r)
	})
}
