package server

import (
	"context"
	"log"
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
		pluginCtx := &plugins.PluginContext{}
		s.pluginManager.ExecutePlugins(pluginCtx, r)

		req := msgPool.Get().(*dns.Msg)
		defer func() {
			*req = dns.Msg{}
			msgPool.Put(req)
		}()

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

	log.Printf("ASTRACAT DNS Resolver is running on %s", s.config.ListenAddr)
	select {} // Block forever
}

func (s *Server) startListener(net string) {
	server := &dns.Server{Addr: s.config.ListenAddr, Net: net, Handler: s.handler}
	log.Printf("Starting %s listener on %s", net, s.config.ListenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to start %s listener: %s", net, err)
	}
}

// metricsWrapper is a middleware that increments the query counter.
func (s *Server) metricsWrapper(h dns.Handler) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.metrics.IncrementQueries()
		h.ServeDNS(w, r)
	})
}
