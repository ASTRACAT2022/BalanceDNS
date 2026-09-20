package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"balancedns/internal/cache"
	"balancedns/internal/config"
	"balancedns/internal/hosts"
	"balancedns/internal/logx"
	"balancedns/internal/metrics"
	"balancedns/internal/plugin"
	"balancedns/internal/router"
	"balancedns/internal/threat"
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
	hosts    *hosts.Table
	acl      []*net.IPNet

	chain     []string
	blacklist *blacklistIndex
	tenants   *tenantStore
	threat    *threat.Manager

	// cnamesGlue caches live-resolved A/AAAA glue (IPs) for CNAME targets so a
	// CNAME answer can inline the target's addresses. TTL 60s per entry.
	cnamesGlue sync.Map // map[string]cnamesGlueEntry

	// dotConfigID maps a DoT client remote-address to the tenant config_id
	// selected by SNI ({config_id}.dns.astracat.network) at TLS handshake.
	// Populated by runDoTComponent's GetConfigForClient; consumed by handleDNS
	// so per-tenant rules apply to per-tenant DoT connections.
	dotConfigID sync.Map // map[string]string (remoteAddr -> config_id)

	supervisor *control.Supervisor

	queryLog *queryLogger
}

// blacklistRule — одно правило чёрного списка.
type blacklistRule struct {
	suffix bool
	value  string
}

// blacklistIndex — индексированный чёрный список для O(1) lookup.
// Точные правила хранятся в map, суффиксные проверяются по меткам домена.
// Это критично для больших списков (100K+ доменов): линейный поиск по всем
// правилам на каждый запрос был бы O(N) и упирался бы в CPU под нагрузкой.
type blacklistIndex struct {
	exact   map[string]struct{} // точные домены (без суффиксного совпадения)
	suffix  map[string]struct{} // суффиксные домены (блокируют поддомены)
}

func newBlacklistIndex() *blacklistIndex {
	return &blacklistIndex{
		exact:  make(map[string]struct{}),
		suffix: make(map[string]struct{}),
	}
}

func (b *blacklistIndex) add(rule blacklistRule) {
	if rule.suffix {
		b.suffix[rule.value] = struct{}{}
	} else {
		b.exact[rule.value] = struct{}{}
	}
}

func (b *blacklistIndex) contains(name string) bool {
	normalized := normalizeDomain(name)
	if _, ok := b.exact[normalized]; ok {
		return true
	}
	// Суффиксные правила: проверяем сам домен и каждую суффиксную
	// последовательность меток. "sub.example.com" → проверяем
	// "sub.example.com", "example.com", "com". O(число меток), а не O(число правил).
	if _, ok := b.suffix[normalized]; ok {
		return true
	}
	for {
		idx := strings.IndexByte(normalized, '.')
		if idx < 0 {
			break
		}
		normalized = normalized[idx+1:]
		if _, ok := b.suffix[normalized]; ok {
			return true
		}
	}
	return false
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
		c = cache.NewWithMetrics(cfg.Cache.Capacity, cfg.Cache.MinTTLSeconds, cfg.Cache.MaxTTLSeconds, m)
	}

	var engine *plugin.Engine
	var threatMgr *threat.Manager
	if cfg.Plugins.Enabled && len(cfg.Plugins.Entries) > 0 {
		// Build the Threat Intelligence manager first (if enabled) so its Lua
		// hook can be threaded into the policy engine's sandboxes.
		if cfg.Threat != nil && cfg.Threat.Enabled {
			threatCfg := threatConfigFrom(cfg.Threat)
			threatMgr, err = threat.NewManager(threatCfg, m.Registry())
			if err != nil {
				return nil, fmt.Errorf("threat intelligence: %w", err)
			}
		}

		var hook plugin.LuaHook
		if threatMgr != nil {
			hook = plugin.NewThreatLuaHook(threatMgr)
		}
		engine, err = plugin.NewEngineWithOptions(cfg.Plugins.Entries, time.Duration(cfg.Plugins.TimeoutMS)*time.Millisecond, m, plugin.EngineOption{LuaHook: hook})
		if err != nil {
			return nil, err
		}
	}

	var hostTable *hosts.Table
	if cfg.Hosts.File != "" {
		hostTable, err = hosts.Load(cfg.Hosts.File, cfg.Hosts.TTL)
		if err != nil {
			return nil, err
		}
	}

	acl, err := parseACL(cfg.ACL)
	if err != nil {
		return nil, err
	}

	blacklist, err := loadBlacklist(cfg.Blacklist)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       cfg,
		logger:    logger,
		metrics:   m,
		cache:     c,
		plugins:   engine,
		resolver:  resolver,
		hosts:     hostTable,
		acl:       acl,
		chain:     normalizeChain(cfg.Routing.Chain),
		blacklist: blacklist,
		threat:    threatMgr,
	}

	if cfg.QueryLog != "" {
		s.queryLog = newQueryLogger(cfg.QueryLog)
	}

	// Загружаем per-tenant правила (мульти-тенантность DoH/DoT).
	if cfg.TenantsDir != "" {
		tenants, err := loadTenants(cfg.TenantsDir)
		if err != nil {
			return nil, err
		}
		s.tenants = tenants
	}

	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", s.handleDNS)

	// Start the Threat Intelligence background updater (non-blocking). It runs
	// alongside the DNS components; the loop stops when ctx is cancelled. DNS
	// serving does not depend on it (fail-open), so zero-downtime is preserved.
	if s.threat != nil && s.threat.Enabled() {
		s.threat.Start(ctx)
	}

	components := []control.ComponentConfig{
		{
			Name:     "dns-udp",
			Required: true,
			Start:    s.runDNSComponent("udp", s.cfg.Listen.DNS, dnsMux),
		},
		{
			Name:     "dns-tcp",
			Required: true,
			Start:    s.runDNSComponent("tcp", s.cfg.Listen.DNS, dnsMux),
		},
		{
			Name:     "metrics-http",
			Required: true,
			Start:    s.runMetricsComponent(),
		},
	}

	if s.cfg.Listen.DoT != "" {
		components = append(components, control.ComponentConfig{
			Name:     "dns-dot",
			Required: true,
			Start:    s.runDoTComponent(dnsMux),
		})
	}
	if s.cfg.Listen.DoH != "" {
		components = append(components, control.ComponentConfig{
			Name:     "dns-doh",
			Required: true,
			Start:    s.runDoHComponent(),
		})
	}

	s.supervisor = control.New(s.logger, s.metrics, components, control.Options{
		RestartBackoff:      time.Duration(s.cfg.Control.RestartBackoffMS) * time.Millisecond,
		RestartMaxBackoff:   time.Duration(s.cfg.Control.RestartMaxBackoffMS) * time.Millisecond,
		MaxConsecutiveFails: s.cfg.Control.MaxConsecutiveFailure,
		MinStableRun:        time.Duration(s.cfg.Control.MinStableRunMS) * time.Millisecond,
	})

	s.logger.Infof("control plane started: components=%d", len(components))

	// Периодическая перезагрузка per-tenant правил (Node Agent обновляет
	// файлы каждые ~60с). Без простоев: атомарная замена через RWMutex.
	if s.tenants != nil && s.cfg.TenantsDir != "" {
		go s.tenantReloadLoop(ctx)
	}

	err := s.supervisor.Run(ctx)
	if err != nil {
		return err
	}
	s.logger.Infof("graceful shutdown completed")
	return nil
}

// tenantReloadLoop периодически перезагружает per-tenant правила.
func (s *Server) tenantReloadLoop(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.tenants.reload(s.cfg.TenantsDir); err != nil {
				s.logger.Errorf("tenant reload failed: %v", err)
			}
		}
	}
}

func (s *Server) runDNSComponent(network, addr string, handler dns.Handler) func(context.Context) error {
	return func(ctx context.Context) error {
		srv := &dns.Server{
			Addr:         addr,
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

		s.logger.Infof("%s component started on %s", network, addr)
		err := srv.ListenAndServe()
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("%s listener failed: %w", network, err)
	}
}

func (s *Server) runDoTComponent(handler dns.Handler) func(context.Context) error {
	return func(ctx context.Context) error {
		cert, err := tls.LoadX509KeyPair(s.cfg.Listen.TLSCertFile, s.cfg.Listen.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load dot certificate: %w", err)
		}

		srv := &dns.Server{
			Addr:         s.cfg.Listen.DoT,
			Net:          "tcp-tls",
			Handler:      handler,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
				// Персональный DoT: определяем tenant по SNI (поддомену) при
				// TLS-handshake, например ed2x.dns.astracat.network → config_id.
				// SNI не является поддоменом — используем дефолтный конфиг и не
				// ломаем обычный DoT (возвращаем nil).
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					if cid := s.tenantForSNI(hello.ServerName); cid != "" {
						if conn, ok := hello.Conn.(net.Conn); ok {
							s.dotConfigID.Store(conn.RemoteAddr().String(), cid)
						}
					}
					return nil, nil
				},
			},
		}

		go func() {
			<-ctx.Done()
			_ = srv.Shutdown()
		}()

		s.logger.Infof("dot component started on %s", s.cfg.Listen.DoT)
		err = srv.ListenAndServe()
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("dot listener failed: %w", err)
	}
}

// tenantForSNI определяет config_id по SNI (ServerName) для персонального DoT.
// Формат: {config_id}.dns.astracat.network → config_id. Возвращает "" если SNI
// не является известным тенантом (тогда применяются глобальные правила).
func (s *Server) tenantForSNI(serverName string) string {
	if serverName == "" || s.tenants == nil {
		return ""
	}
	host := serverName
	if h, _, err := net.SplitHostPort(serverName); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// Ищем поддомен вида {config_id}.dns.astracat.network → левая часть = config_id.
	parts := strings.Split(host, ".")
	if len(parts) >= 4 {
		cid := parts[0]
		if s.tenants.get(cid) != nil {
			return cid
		}
	}
	return ""
}

func (s *Server) runDoHComponent() func(context.Context) error {
	return func(ctx context.Context) error {
		// Обрабатываем и /dns-query, и /{config_id}, и /{config_id}/dns-query
		// (NextDNS-стиль: config_id в пути DoH URL).
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleDoH)

		server := &http.Server{
			Addr:         s.cfg.Listen.DoH,
			Handler:      mux,
			ReadTimeout:  time.Duration(s.cfg.Listen.ReadTimeoutMS) * time.Millisecond,
			WriteTimeout: time.Duration(s.cfg.Listen.WriteTimeoutMS) * time.Millisecond,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()

		s.logger.Infof("doh component started on %s%s", s.cfg.Listen.DoH, s.cfg.Listen.DoHPath)
		err := server.ListenAndServeTLS(s.cfg.Listen.TLSCertFile, s.cfg.Listen.TLSKeyFile)
		if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("doh listener failed: %w", err)
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
	defer func() {
		if r := recover(); r != nil {
			s.logger.Errorf("panic in dns handler: %v", r)
			// Best-effort SERVFAIL so the client gets a response instead of a hang.
			// Оборачиваем в отдельный recover: если w уже закрыт, вторая паника
			// не должна ронять горутину.
			if req != nil {
				func() {
					defer func() { _ = recover() }()
					_ = w.WriteMsg(s.rcodeResponse(req, dns.RcodeServerFailure))
				}()
			}
		}
	}()
	respp := ""
	// Персональный DoT: если для этого соединения при TLS-handshake был
	// выбран tenant по SNI, применяем его per-tenant правила.
	if cid, ok := s.dotConfigID.Load(w.RemoteAddr().String()); ok {
		if c, ok2 := cid.(string); ok2 {
			respp = c
		}
	}
	resp := s.resolveDNS(req, w.RemoteAddr(), protocolFromNet(w.LocalAddr()), respp)
	if resp == nil {
		// DROP: responder decided to send no reply (e.g. threat block_rcode).
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Errorf("write dns response: %v", err)
	}
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remoteIP := remoteIPFromString(r.RemoteAddr)
	if !s.allowedRemoteIP(remoteIP) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	wire, err := readDoHWireMessage(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		http.Error(w, "invalid dns message", http.StatusBadRequest)
		return
	}

	// Извлекаем config_id из пути DoH URL (NextDNS-стиль):
	//   /dns-query            → default (без tenant)
	//   /{config_id}          → tenant
	//   /{config_id}/dns-query → tenant
	configID := configIDFromDoHPath(r.URL.Path, s.cfg.Listen.DoHPath)

	resp := s.resolveDNS(req, &net.TCPAddr{IP: remoteIP}, "doh", configID)
	if resp == nil {
		// DROP: responder decided to send no reply (e.g. threat block_rcode).
		return
	}
	payload, err := resp.Pack()
	if err != nil {
		http.Error(w, "encode dns response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// configIDFromDoHPath извлекает config_id из пути DoH URL.
// Поддерживаются форматы: /dns-query, /{config_id}, /{config_id}/dns-query.
func configIDFromDoHPath(path, dohPath string) string {
	p := strings.Trim(path, "/")
	if p == "" {
		return ""
	}
	// /dns-query → default
	if p == strings.Trim(dohPath, "/") {
		return ""
	}
	// /{config_id} или /{config_id}/dns-query
	segments := strings.Split(p, "/")
	if len(segments) == 0 {
		return ""
	}
	cid := segments[0]
	if cid == strings.Trim(dohPath, "/") {
		return ""
	}
	return cid
}

func readDoHWireMessage(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		encoded := strings.TrimSpace(r.URL.Query().Get("dns"))
		if encoded == "" {
			return nil, errors.New("missing dns query parameter")
		}
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("invalid dns query parameter")
		}
		return data, nil
	case http.MethodPost:
		defer r.Body.Close()
		data, err := io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			return nil, errors.New("failed to read request body")
		}
		if len(data) == 0 {
			return nil, errors.New("empty request body")
		}
		return data, nil
	default:
		return nil, errors.New("unsupported method")
	}
}

func (s *Server) resolveDNS(req *dns.Msg, remoteAddr net.Addr, protocol string, configID string) *dns.Msg {
	protocol = metrics.ProtocolLabel(protocol)

	if len(req.Question) == 0 {
		s.metrics.IncQueries(protocol, "OTHER")
		s.metrics.IncResponse(metrics.RcodeLabel(dns.RcodeFormatError))
		return s.rcodeResponse(req, dns.RcodeFormatError)
	}

	if !s.allowedRemoteIP(remoteIPFromNetAddr(remoteAddr)) {
		s.metrics.IncQueries(protocol, metrics.QueryTypeLabel(req.Question[0].Qtype))
		s.metrics.IncResponse(metrics.RcodeLabel(dns.RcodeRefused))
		return s.rcodeResponse(req, dns.RcodeRefused)
	}

	current := normalizeQuestion(req.Question[0])
	qtypeLabel := metrics.QueryTypeLabel(current.Qtype)

	// Per-tenant правила: если config_id задан (DoH/DoT), применяем ТОЛЬКО
	// правила этого tenant (изоляция). Если config_id пуст (обычный DNS) —
	// глобальные правила.
	var tenant *tenantRules
	if s.tenants != nil {
		tenant = s.tenants.get(configID)
	}

	s.metrics.IncQueries(protocol, qtypeLabel)
	s.metrics.IncQueriesInFlight()
	defer s.metrics.DecQueriesInFlight()
	start := time.Now()

	remote := "<unknown>"
	if remoteAddr != nil {
		remote = remoteAddr.String()
	}
	s.logger.Queryf("query id=%d remote=%s domain=%s type=%s", req.Id, remote, current.Name, dns.TypeToString[current.Qtype])

	var resp *dns.Msg
	dropped := false
	for _, stage := range s.chain {
		switch stage {
		case "blacklist":
			// Allowlist (исключение) имеет приоритет над blacklist.
			if tenant != nil && tenant.isAllowed(current.Name) {
				continue
			}
			// Per-tenant blacklist (если config_id задан) или глобальный.
			if tenant != nil {
				if tenant.blacklist != nil && tenant.blacklist.contains(current.Name) {
					s.logger.Debugf("blocked domain %s (tenant %s)", current.Name, tenant.configID)
					resp = s.rcodeResponse(req, dns.RcodeRefused)
					goto done
				}
			} else if s.isBlocked(current.Name) {
				s.logger.Debugf("blocked domain %s", current.Name)
				resp = s.rcodeResponse(req, dns.RcodeRefused)
				goto done
			}

		case "hosts":
			// Per-tenant hosts (если config_id задан) или глобальный.
			if tenant != nil {
				if ips, ok := tenant.lookupHost(current.Name, current.Qtype); ok {
					resp = s.localDataResponse(req, current, plugin.LocalData{IPs: ips, TTL: 120})
					goto done
				}
			} else if s.hosts != nil {
				if ans, ok := s.hosts.Lookup(current.Name, current.Qtype); ok {
					resp = s.localDataResponse(req, current, plugin.LocalData{IPs: ans.IPs, TTL: ans.TTL})
					goto done
				}
			}

		case "cache":
			if s.cache == nil {
				continue
			}
			if cached, ok := s.cache.Get(current); ok {
				s.metrics.IncCacheHits()
				cached.Id = req.Id
				cached.Question = []dns.Question{current}
				resp = cached
				goto done
			}
			s.metrics.IncCacheMisses()

		case "lua_policy", "plugin", "plugins", "lua":
			if s.plugins == nil {
				continue
			}
			decision, err := s.plugins.Decide(current)
			if err != nil {
				s.logger.Errorf("plugin execution error for %s: %v", current.Name, err)
				continue
			}
			switch decision.Action {
			case plugin.ActionBlock:
				// Honor the configured block response: REFUSED (legacy default),
				// NXDOMAIN, or DROP (send no response).
				switch s.cfg.Plugins.BlockRcode {
				case "NXDOMAIN":
					resp = s.rcodeResponse(req, dns.RcodeNameError)
				case "DROP":
					dropped = true
					resp = nil
				default: // REFUSED
					resp = s.rcodeResponse(req, dns.RcodeRefused)
				}
				goto done
			case plugin.ActionLocalData:
				resp = s.localDataResponse(req, decision.Question, decision.Local)
				goto done
			case plugin.ActionRewrite, plugin.ActionForward:
				current = normalizeQuestion(decision.Question)
			}

		case "upstream":
			var fwdErr error
			resp, _, fwdErr = s.resolver.Forward(context.Background(), req, current)
			if fwdErr != nil {
				s.logger.Errorf("upstream forward failed for %s: %v", current.Name, fwdErr)
				resp = s.rcodeResponse(req, dns.RcodeServerFailure)
				goto done
			}
			if resp == nil {
				s.logger.Errorf("upstream returned nil response for %s", current.Name)
				resp = s.rcodeResponse(req, dns.RcodeServerFailure)
				goto done
			}
			if s.cache != nil && resp.Rcode == dns.RcodeSuccess {
				s.cache.Set(current, resp)
			}
			s.logger.Debugf("upstream served domain=%s type=%s", current.Name, dns.TypeToString[current.Qtype])
			goto done
		default:
			s.logger.Debugf("unknown chain stage: %s", stage)
		}
	}

	resp = s.rcodeResponse(req, dns.RcodeServerFailure)

done:
	if !dropped && resp == nil {
		resp = s.rcodeResponse(req, dns.RcodeServerFailure)
	}
	if dropped {
		// DROP: send no response at all. Log and count it, return nil so the
		// transport handlers skip writing.
		if s.queryLog != nil {
			s.queryLog.Log(current.Name, current.Qtype, -1, protocol, configID)
		}
		s.metrics.ObserveQuery(protocol, qtypeLabel, "DROP", time.Since(start))
		s.metrics.IncResponse("DROP")
		return nil
	}
	if s.queryLog != nil {
		s.queryLog.Log(current.Name, current.Qtype, resp.Rcode, protocol, configID)
	}
	s.metrics.ObserveQuery(protocol, qtypeLabel, metrics.RcodeLabel(resp.Rcode), time.Since(start))
	s.metrics.IncResponse(metrics.RcodeLabel(resp.Rcode))
	return resp
}

// cnamesGlueEntry caches live-resolved glue IPs for a CNAME target.
type cnamesGlueEntry struct {
	ips    []net.IP
	expiry time.Time
}

// cnameGlueResolvers are the public recursive resolvers used to resolve a CNAME
// target's A/AAAA records inline. Tried in order; falls back on failure.
// Directly via dns.Client (NOT s.resolver.Forward) because the request-handler
// path is unreliable inside a query context.
var cnameGlueResolvers = []string{"9.9.9.9:53", "1.1.1.1:53", "8.8.8.8:53"}

// resolveCNAMEChain resolves the A/AAAA records of a CNAME target through public
// resolvers and returns them deduplicated. Results are cached for 60s. If all
// resolvers fail, it returns false (the caller replies with CNAME only).
func (s *Server) resolveCNAMEChain(ctx context.Context, target string) ([]net.IP, bool) {
	// Fast path: warm cache.
	if v, ok := s.cnamesGlue.Load(target); ok {
		e := v.(cnamesGlueEntry)
		if time.Now().Before(e.expiry) {
			return e.ips, true
		}
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(target), dns.TypeA)

	dedup := make(map[string]bool)
	var ips []net.IP
	var lastErr error

	client := &dns.Client{Timeout: 5 * time.Second}
	for _, addr := range cnameGlueResolvers {
		resp, _, err := client.Exchange(msg, addr)
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range resp.Answer {
			switch r := rr.(type) {
			case *dns.A:
				if r.A != nil && !dedup[r.A.String()] {
					dedup[r.A.String()] = true
					ips = append(ips, r.A)
				}
			}
		}
		// AAAA pass: merge v6 glue.
		msg6 := new(dns.Msg)
		msg6.SetQuestion(dns.Fqdn(target), dns.TypeAAAA)
		resp6, _, err6 := client.Exchange(msg6, addr)
		if err6 == nil {
			for _, rr := range resp6.Answer {
				if a, ok := rr.(*dns.AAAA); ok && a.AAAA != nil && !dedup[a.AAAA.String()] {
					dedup[a.AAAA.String()] = true
					ips = append(ips, a.AAAA)
				}
			}
		}
		if len(ips) > 0 {
			break
		}
	}

	if len(ips) == 0 {
		if lastErr != nil {
			s.logger.Debugf("resolveCNAMEChain(%s): no glue resolved: %v", target, lastErr)
		}
		return nil, false
	}

	s.cnamesGlue.Store(target, cnamesGlueEntry{ips: ips, expiry: time.Now().Add(60 * time.Second)})
	return ips, true
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

	// Explicit CNAME answer.
	if local.CNAME != "" {
		// CNAME record: q.Name -> local.CNAME.
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: local.CNAME,
		})

		// For A/AAAA/ANY queries, attach glue for the CNAME target: either from
		// the policy (local.IPs) or resolved live.
		glue := local.IPs
		if len(glue) == 0 && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) {
			if resolved, ok := s.resolveCNAMEChain(context.Background(), local.CNAME); ok {
				glue = resolved
			}
		}

		for _, ip := range glue {
			switch {
			case q.Qtype == dns.TypeA && ip.To4() != nil:
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: local.CNAME, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip.To4()})
			case q.Qtype == dns.TypeAAAA && ip.To16() != nil && ip.To4() == nil:
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: local.CNAME, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: ip.To16()})
			case q.Qtype == dns.TypeANY:
				if ip.To4() != nil {
					resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: local.CNAME, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: ip.To4()})
				} else if ip.To16() != nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: local.CNAME, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: ip.To16()})
				}
			}
		}

		// NODATA semantics for non-address queries against a CNAME target:
		// return an empty AA reply so clients don't chase a bogus forward.
		return resp
	}

	// Classic A/AAAA/ANY local data (no CNAME).
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
	if s.blacklist == nil {
		return false
	}
	return s.blacklist.contains(name)
}

func (s *Server) rcodeResponse(req *dns.Msg, rcode int) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetRcode(req, rcode)
	return msg
}

func parseBlacklist(domains []string) *blacklistIndex {
	idx := newBlacklistIndex()
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			// "*.ads.com" → суффиксное правило на "ads.com" (без ведущей точки).
			idx.add(blacklistRule{suffix: true, value: normalizeDomain(strings.TrimPrefix(d, "*."))})
			continue
		}
		if strings.HasPrefix(d, ".") {
			// ".tracker.net" → суффиксное правило на "tracker.net" (без ведущей точки).
			idx.add(blacklistRule{suffix: true, value: normalizeDomain(strings.TrimPrefix(d, "."))})
			continue
		}
		idx.add(blacklistRule{value: normalizeDomain(d)})
	}
	return idx
}

// loadBlacklist загружает чёрный список из конфига: домены из inline-списка
// (blacklist.domains) и/или из файла (blacklist.file). Файл поддерживается для
// больших списков (100K+ доменов), которые генерирует Node Agent.
func loadBlacklist(cfg config.BlacklistConfig) (*blacklistIndex, error) {
	idx := parseBlacklist(cfg.Domains)

	if cfg.File == "" {
		return idx, nil
	}

	data, err := os.ReadFile(cfg.File)
	if err != nil {
		return nil, fmt.Errorf("read blacklist file %q: %w", cfg.File, err)
	}

	parseBlacklistFileInto(idx, string(data))
	return idx, nil
}

// parseBlacklistFile разбирает содержимое файла чёрного списка:
// по одному домену на строку, комментарии (#) и пустые строки игнорируются.
// Поддерживаются префиксы "*." и "." для суффиксных правил.
func parseBlacklistFileInto(idx *blacklistIndex, content string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Убираем inline-комментарий.
		if c := strings.Index(line, "#"); c >= 0 {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "*.") {
			idx.add(blacklistRule{suffix: true, value: normalizeDomain(strings.TrimPrefix(line, "*."))})
			continue
		}
		if strings.HasPrefix(line, ".") {
			idx.add(blacklistRule{suffix: true, value: normalizeDomain(strings.TrimPrefix(line, "."))})
			continue
		}
		idx.add(blacklistRule{value: normalizeDomain(line)})
	}
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
		return []string{"blacklist", "hosts", "cache", "lua_policy", "upstream"}
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

func parseACL(values []string) ([]*net.IPNet, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(values))
	for i, value := range values {
		netmask, err := parseCIDROrIP(value)
		if err != nil {
			return nil, fmt.Errorf("acl[%d]: %w", i, err)
		}
		out = append(out, netmask)
	}
	return out, nil
}

func parseCIDROrIP(value string) (*net.IPNet, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil, errors.New("empty ACL value")
	}
	if _, ipnet, err := net.ParseCIDR(v); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR/IP %q", value)
	}
	if ip.To4() != nil {
		_, ipnet, _ := net.ParseCIDR(ip.String() + "/32")
		return ipnet, nil
	}
	_, ipnet, _ := net.ParseCIDR(ip.String() + "/128")
	return ipnet, nil
}

func (s *Server) allowedRemoteIP(ip net.IP) bool {
	if len(s.acl) == 0 {
		return true
	}
	if ip == nil {
		return false
	}
	for _, netmask := range s.acl {
		if netmask.Contains(ip) {
			return true
		}
	}
	return false
}

func protocolFromNet(addr net.Addr) string {
	if addr == nil {
		return "other"
	}
	switch addr.(type) {
	case *net.UDPAddr:
		return "udp"
	case *net.TCPAddr:
		return "tcp"
	default:
		return "other"
	}
}

func remoteIPFromNetAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	default:
		return remoteIPFromString(addr.String())
	}
}

func remoteIPFromString(raw string) net.IP {
	host := strings.TrimSpace(raw)
	if host == "" {
		return nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

// queryLogger пишет DNS-запросы в JSON-lines файл асинхронно (для аналитики).
// Запись идёт через буферизованный канал, чтобы не блокировать обработку DNS.
// Формат строки совместим с Node Agent (agent/analytics.go):
//
//	{"config_id":"","domain":"...","blocked":bool,"qtype":"A","ts":<ms>}
type queryLogger struct {
	path string
	ch   chan queryLogEntry
	w    *bufio.Writer
	f    *os.File
}

type queryLogEntry struct {
	ConfigID string `json:"config_id"`
	Domain   string `json:"domain"`
	Blocked  bool   `json:"blocked"`
	Qtype    string `json:"qtype"`
	Ts       int64  `json:"ts"`
}

func newQueryLogger(path string) *queryLogger {
	ql := &queryLogger{
		path: path,
		ch:   make(chan queryLogEntry, 4096),
	}
	go ql.run()
	return ql
}

func (ql *queryLogger) run() {
	f, err := os.OpenFile(ql.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	ql.f = f
	ql.w = bufio.NewWriterSize(f, 64*1024)

	// Периодический flush, чтобы данные не задерживались в буфере при низком трафике.
	flushTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()

	for {
		select {
		case e, ok := <-ql.ch:
			if !ok {
				_ = ql.w.Flush()
				_ = f.Close()
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			if _, err := ql.w.Write(data); err != nil {
				continue
			}
			if err := ql.w.WriteByte('\n'); err != nil {
				continue
			}
			// Flush при заполнении буфера.
			if ql.w.Buffered() >= 64*1024 {
				_ = ql.w.Flush()
			}
		case <-flushTicker.C:
			if ql.w != nil && ql.w.Buffered() > 0 {
				_ = ql.w.Flush()
			}
		}
	}
}

// Log ставит запись в очередь. Не блокирует вызывающий код (drop при переполнении).
func (ql *queryLogger) Log(domain string, qtype uint16, rcode int, protocol, configID string) {
	if ql == nil {
		return
	}
	entry := queryLogEntry{
		ConfigID: configID,
		Domain:   strings.TrimSuffix(strings.ToLower(domain), "."),
		Blocked:  rcode == dns.RcodeRefused,
		Qtype:    dns.TypeToString[qtype],
		Ts:       time.Now().UnixMilli(),
	}
	select {
	case ql.ch <- entry:
	default:
		// Канал переполнен — пропускаем, чтобы не блокировать DNS.
	}
}

// ---- Per-tenant (мульти-тенантность) ----

// tenantRules — правила одного config_id (пользователя).
// Каждый tenant изолирован: применяются ТОЛЬКО его правила, никогда не
// объединяются с правилами других пользователей.
type tenantRules struct {
	configID  string
	blacklist *blacklistIndex // <config_id>.blacklist
	hosts     map[string][]net.IP // <config_id>.hosts (IP domain)
	allowlist map[string]struct{} // <config_id>.allowlist (домены-исключения)
	security  bool              // <config_id>.security == "1"
}

// tenantStore — хранилище правил всех тенантов.
// Загружается при старте и периодически перезагружается (Node Agent
// обновляет файлы каждые ~60с). Атомарная замена через RWMutex.
type tenantStore struct {
	mu      sync.RWMutex
	tenants map[string]*tenantRules
}

func newTenantStore() *tenantStore {
	return &tenantStore{tenants: make(map[string]*tenantRules)}
}

// loadTenants читает директорию tenants/ и загружает правила всех config_id.
// Формат файлов (генерирует Node Agent):
//   <config_id>.blacklist  — домены по одному на строку
//   <config_id>.hosts      — "IP domain" (как hosts.txt)
//   <config_id>.allowlist  — домены-исключения
//   <config_id>.security   — "1" если включены security-фиды
func loadTenants(dir string) (*tenantStore, error) {
	store := newTenantStore()
	if dir == "" {
		return store, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read tenants dir %q: %w", dir, err)
	}

	// Собираем config_id из файлов.
	configIDs := make(map[string]struct{})
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Пропускаем общий security.blacklist.
		if name == "security.blacklist" {
			continue
		}
		for _, suffix := range []string{".blacklist", ".hosts", ".allowlist", ".security"} {
			if strings.HasSuffix(name, suffix) {
				configIDs[strings.TrimSuffix(name, suffix)] = struct{}{}
				break
			}
		}
	}

	for cid := range configIDs {
		rules := &tenantRules{configID: cid}
		rules.blacklist = newBlacklistIndex()
		rules.hosts = make(map[string][]net.IP)
		rules.allowlist = make(map[string]struct{})

		// Blacklist.
		if data, err := os.ReadFile(filepath.Join(dir, cid+".blacklist")); err == nil {
			parseBlacklistFileInto(rules.blacklist, string(data))
		}
		// Allowlist.
		if data, err := os.ReadFile(filepath.Join(dir, cid+".allowlist")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				rules.allowlist[normalizeDomain(line)] = struct{}{}
			}
		}
		// Hosts.
		if data, err := os.ReadFile(filepath.Join(dir, cid+".hosts")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				ip := net.ParseIP(fields[0])
				if ip == nil {
					continue
				}
				for _, name := range fields[1:] {
					rules.hosts[normalizeDomain(name)] = append(rules.hosts[normalizeDomain(name)], ip)
				}
			}
		}
		// Security flag.
		if data, err := os.ReadFile(filepath.Join(dir, cid+".security")); err == nil {
			rules.security = strings.TrimSpace(string(data)) == "1"
		}

		store.tenants[cid] = rules
	}

	return store, nil
}

// get возвращает правила для config_id. Если tenant не найден — nil.
func (s *tenantStore) get(configID string) *tenantRules {
	if s == nil || configID == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenants[configID]
}

// reload перезагружает правила из директории (атомарно).
func (s *tenantStore) reload(dir string) error {
	newStore, err := loadTenants(dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.tenants = newStore.tenants
	s.mu.Unlock()
	return nil
}

// isAllowed возвращает true, если домен в allowlist (исключение).
func (t *tenantRules) isAllowed(name string) bool {
	if t == nil {
		return false
	}
	_, ok := t.allowlist[normalizeDomain(name)]
	return ok
}

// lookupHost возвращает IP для домена из tenant hosts.
func (t *tenantRules) lookupHost(name string, qtype uint16) ([]net.IP, bool) {
	if t == nil {
		return nil, false
	}
	ips, ok := t.hosts[normalizeDomain(name)]
	if !ok {
		return nil, false
	}
	// Фильтруем по qtype (A/AAAA).
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		switch qtype {
		case dns.TypeA:
			if v4 := ip.To4(); v4 != nil {
				out = append(out, v4)
			}
		case dns.TypeAAAA:
			if ip.To16() != nil && ip.To4() == nil {
				out = append(out, ip)
			}
		case dns.TypeANY:
			out = append(out, ip)
		}
	}
	return out, len(out) > 0
}

