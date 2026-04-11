package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"balancedns/internal/cache"
	"balancedns/internal/config"
	"balancedns/internal/logx"
	"balancedns/internal/metrics"
	"balancedns/internal/plugin"
	"balancedns/internal/router"
	control "balancedns/internal/runtime"

	"github.com/miekg/dns"
)

type Server struct {
	cfg      *config.Config
	logger   *logx.Logger
	metrics  *metrics.Provider
	cache    *cache.Cache
	plugins  *plugin.Engine
	resolver *router.Resolver

	chain     []string
	blacklist []blacklistRule

	supervisor *control.Supervisor
}

type blacklistRule struct {
	suffix bool
	value  string
}

func New(cfg *config.Config) (*Server, error) {
	m := metrics.New()
	logger := logx.New(cfg.Logging.Level, cfg.Logging.LogQueries)

	resolver, err := router.NewResolver(cfg.Upstreams, m)
	if err != nil {
		return nil, err
	}

	var c *cache.Cache
	if cfg.Cache.Enabled {
		c = cache.New(cfg.Cache.Capacity, cfg.Cache.MinTTLSeconds, cfg.Cache.MaxTTLSeconds)
	}

	var engine *plugin.Engine
	if cfg.Plugins.Enabled && len(cfg.Plugins.Entries) > 0 {
		engine, err = plugin.NewEngine(cfg.Plugins.Entries, time.Duration(cfg.Plugins.TimeoutMS)*time.Millisecond)
		if err != nil {
			return nil, err
		}
	}

	s := &Server{
		cfg:       cfg,
		logger:    logger,
		metrics:   m,
		cache:     c,
		plugins:   engine,
		resolver:  resolver,
		chain:     normalizeChain(cfg.Routing.Chain),
		blacklist: parseBlacklist(cfg.Blacklist.Domains),
	}

	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", s.handleDNS)

	components := []control.ComponentConfig{
		{
			Name:     "dns-udp",
			Required: true,
			Start:    s.runDNSComponent("udp", dnsMux),
		},
		{
			Name:     "dns-tcp",
			Required: true,
			Start:    s.runDNSComponent("tcp", dnsMux),
		},
		{
			Name:     "metrics-http",
			Required: true,
			Start:    s.runMetricsComponent(),
		},
	}

	s.supervisor = control.New(s.logger, s.metrics, components, control.Options{
		RestartBackoff:      time.Duration(s.cfg.Control.RestartBackoffMS) * time.Millisecond,
		RestartMaxBackoff:   time.Duration(s.cfg.Control.RestartMaxBackoffMS) * time.Millisecond,
		MaxConsecutiveFails: s.cfg.Control.MaxConsecutiveFailure,
		MinStableRun:        time.Duration(s.cfg.Control.MinStableRunMS) * time.Millisecond,
	})

	s.logger.Infof("control plane started: components=%d", len(components))
	err := s.supervisor.Run(ctx)
	if err != nil {
		return err
	}
	s.logger.Infof("graceful shutdown completed")
	return nil
}

func (s *Server) runDNSComponent(network string, handler dns.Handler) func(context.Context) error {
	return func(ctx context.Context) error {
		srv := &dns.Server{
			Addr:         s.cfg.Listen.DNS,
			Net:          network,
			Handler:      handler,
			ReusePort:    s.cfg.Listen.ReusePort,
			ReuseAddr:    s.cfg.Listen.ReuseAddr,
			UDPSize:      s.cfg.Listen.UDPSize,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
		}

		go func() {
			<-ctx.Done()
			_ = srv.Shutdown()
		}()

		s.logger.Infof("%s component started on %s", network, s.cfg.Listen.DNS)
		err := srv.ListenAndServe()
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("%s listener failed: %w", network, err)
	}
}

func (s *Server) runMetricsComponent() func(context.Context) error {
	return func(ctx context.Context) error {
		mux := http.NewServeMux()
		mux.Handle("/metrics", s.metrics.Handler())
		mux.HandleFunc("/healthz", s.handleHealthz)
		mux.HandleFunc("/readyz", s.handleReadyz)
		mux.HandleFunc("/statusz", s.handleStatusz)

		server := &http.Server{
			Addr:         s.cfg.Listen.Metrics,
			Handler:      mux,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()

		s.logger.Infof("metrics component started on %s", s.cfg.Listen.Metrics)
		err := server.ListenAndServe()
		if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("metrics listener failed: %w", err)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.writeSupervisorStatus(w, s.supervisor.Healthy(true))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	s.writeSupervisorStatus(w, s.supervisor.Healthy(true))
}

func (s *Server) handleStatusz(w http.ResponseWriter, _ *http.Request) {
	s.writeSupervisorStatus(w, true)
}

func (s *Server) writeSupervisorStatus(w http.ResponseWriter, healthy bool) {
	if s.supervisor == nil {
		http.Error(w, "supervisor not initialized", http.StatusServiceUnavailable)
		return
	}

	resp := struct {
		Status     string          `json:"status"`
		Timestamp  time.Time       `json:"timestamp"`
		Components []control.State `json:"components"`
	}{
		Status:     "ok",
		Timestamp:  time.Now().UTC(),
		Components: s.supervisor.Snapshot(),
	}
	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		resp.Status = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	s.metrics.IncQueries()
	if len(req.Question) == 0 {
		s.writeRcode(w, req, dns.RcodeFormatError)
		return
	}

	current := normalizeQuestion(req.Question[0])
	s.logger.Queryf("query id=%d remote=%s domain=%s type=%s", req.Id, w.RemoteAddr(), current.Name, dns.TypeToString[current.Qtype])

	for _, stage := range s.chain {
		switch stage {
		case "blacklist":
			if s.isBlocked(current.Name) {
				s.logger.Debugf("blocked domain %s", current.Name)
				s.writeRcode(w, req, dns.RcodeRefused)
				return
			}

		case "cache":
			if s.cache == nil {
				continue
			}
			if cached, ok := s.cache.Get(current); ok {
				s.metrics.IncCacheHits()
				cached.Id = req.Id
				cached.Question = []dns.Question{current}
				if err := w.WriteMsg(cached); err != nil {
					s.logger.Errorf("write cached response: %v", err)
				}
				return
			}

		case "lua_policy", "plugin", "plugins", "lua":
			if s.plugins == nil {
				continue
			}
			decision, err := s.plugins.Decide(current)
			if err != nil {
				s.metrics.IncPluginErrors()
				s.logger.Errorf("plugin execution error for %s: %v", current.Name, err)
				continue
			}
			switch decision.Action {
			case plugin.ActionBlock:
				s.writeRcode(w, req, dns.RcodeRefused)
				return
			case plugin.ActionLocalData:
				resp := s.localDataResponse(req, decision.Question, decision.Local)
				if err := w.WriteMsg(resp); err != nil {
					s.logger.Errorf("write local data response: %v", err)
				}
				return
			case plugin.ActionRewrite, plugin.ActionForward:
				current = normalizeQuestion(decision.Question)
			}

		case "upstream":
			resp, up, err := s.resolver.Forward(context.Background(), req, current)
			if err != nil {
				s.logger.Errorf("upstream forward failed for %s: %v", current.Name, err)
				s.writeRcode(w, req, dns.RcodeServerFailure)
				return
			}
			if s.cache != nil && resp.Rcode == dns.RcodeSuccess {
				s.cache.Set(current, resp)
			}
			if err := w.WriteMsg(resp); err != nil {
				s.logger.Errorf("write upstream response: %v", err)
			}
			s.logger.Debugf("upstream=%s served domain=%s type=%s", up.Name, current.Name, dns.TypeToString[current.Qtype])
			return
		default:
			s.logger.Debugf("unknown chain stage: %s", stage)
		}
	}

	s.writeRcode(w, req, dns.RcodeServerFailure)
}

func (s *Server) localDataResponse(req *dns.Msg, q dns.Question, local plugin.LocalData) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Question = []dns.Question{q}
	resp.Authoritative = true

	ttl := local.TTL
	if ttl == 0 {
		ttl = 60
	}

	for _, ip := range local.IPs {
		switch {
		case q.Qtype == dns.TypeA && ip.To4() != nil:
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip.To4()})
		case q.Qtype == dns.TypeAAAA && ip.To16() != nil && ip.To4() == nil:
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: ip.To16()})
		case q.Qtype == dns.TypeANY:
			if ip.To4() != nil {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip.To4()})
			} else if ip.To16() != nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: ip.To16()})
			}
		}
	}

	return resp
}

func (s *Server) isBlocked(name string) bool {
	normalized := normalizeDomain(name)
	for _, rule := range s.blacklist {
		if rule.suffix {
			if strings.HasSuffix(normalized, rule.value) {
				return true
			}
			continue
		}
		if normalized == rule.value {
			return true
		}
	}
	return false
}

func (s *Server) writeRcode(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	msg := new(dns.Msg)
	msg.SetRcode(req, rcode)
	if err := w.WriteMsg(msg); err != nil {
		s.logger.Errorf("write rcode response: %v", err)
	}
}

func parseBlacklist(domains []string) []blacklistRule {
	rules := make([]blacklistRule, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			rules = append(rules, blacklistRule{suffix: true, value: normalizeDomain(strings.TrimPrefix(d, "*"))})
			continue
		}
		if strings.HasPrefix(d, ".") {
			rules = append(rules, blacklistRule{suffix: true, value: normalizeDomain(d)})
			continue
		}
		rules = append(rules, blacklistRule{value: normalizeDomain(d)})
	}
	return rules
}

func normalizeChain(chain []string) []string {
	out := make([]string, 0, len(chain))
	for _, stage := range chain {
		n := strings.TrimSpace(strings.ToLower(stage))
		if n != "" {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []string{"blacklist", "cache", "lua_policy", "upstream"}
	}
	return out
}

func normalizeQuestion(q dns.Question) dns.Question {
	q.Name = normalizeDomain(q.Name)
	if q.Qclass == 0 {
		q.Qclass = dns.ClassINET
	}
	return q
}

func normalizeDomain(name string) string {
	return strings.ToLower(dns.Fqdn(strings.TrimSpace(name)))
}
