package admin

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"dns-resolver/internal/config"
	"dns-resolver/internal/dnsproxy"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/hosts"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*
//go:embed static/*
var templatesFS embed.FS

// Server provides an admin web interface.
type Server struct {
	addr          string
	metrics       *metrics.Metrics
	resolver      ControlResolver
	policyUpdater PolicyUpdater
	hosts         *hosts.HostsPlugin
	adblock       *adblock.AdBlockPlugin
	pm            *plugins.PluginManager
	username      string
	passwordHash  []byte
	sessionToken  string
	sessionExpiry time.Time
	configPath    string
	baseConfig    *config.Config
}

// ControlResolver provides resolver control hooks used by admin endpoints.
type ControlResolver interface {
	Reload(rootAnchorPath string) error
	ClearCache(rootAnchorPath string) error
}

// PolicyUpdater applies updated policy rules without restarting the process.
type PolicyUpdater interface {
	UpdatePolicy(opts dnsproxy.ProxyPolicyOptions)
}

type dashboardResponse struct {
	Metrics metrics.DashboardMetrics `json:"metrics"`
	System  configSummary            `json:"system"`
	Plugins []pluginState            `json:"plugins"`
}

type configResponse struct {
	Raw             string        `json:"raw"`
	Summary         configSummary `json:"summary"`
	RequiresRestart bool          `json:"requires_restart"`
}

type configUpdateRequest struct {
	Raw string `json:"raw"`
}

type configUpdateResponse struct {
	Status          string        `json:"status"`
	Message         string        `json:"message"`
	Summary         configSummary `json:"summary"`
	RequiresRestart bool          `json:"requires_restart"`
}

type configSummary struct {
	ListenAddr         string `json:"listen_addr"`
	AdminAddr          string `json:"admin_addr"`
	MetricsAddr        string `json:"metrics_addr"`
	ResolverType       string `json:"resolver_type"`
	DoTAddr            string `json:"dot_addr"`
	ODoHAddr           string `json:"odoh_addr"`
	PrometheusEnabled  bool   `json:"prometheus_enabled"`
	TopDomainsEnabled  bool   `json:"top_domains_enabled"`
	PolicyEnabled      bool   `json:"policy_enabled"`
	HostsEnabled       bool   `json:"hosts_enabled"`
	AdblockEnabled     bool   `json:"adblock_enabled"`
	DNSDistCompat      bool   `json:"dnsdist_compat_enabled"`
	AttackProtection   bool   `json:"attack_protection_enabled"`
	CacheRAMSize       int    `json:"cache_ram_size"`
	CachePath          string `json:"cache_path"`
	HostsPath          string `json:"hosts_path"`
	HostsURL           string `json:"hosts_url"`
	MaxQPSPerIP        int    `json:"max_qps_per_ip"`
	MaxGlobalInflight  int    `json:"max_global_inflight"`
	ResolverWorkers    int    `json:"resolver_workers"`
	MetricsStoragePath string `json:"metrics_storage_path"`
}

type hostsResponse struct {
	Enabled        bool   `json:"enabled"`
	FilePath       string `json:"file_path"`
	HostsURL       string `json:"hosts_url"`
	UpdateInterval string `json:"update_interval"`
	Content        string `json:"content"`
}

type hostsUpdateRequest struct {
	FilePath       string `json:"file_path"`
	HostsURL       string `json:"hosts_url"`
	UpdateInterval string `json:"update_interval"`
	Content        string `json:"content"`
}

type policyResponse struct {
	Enabled         bool                            `json:"enabled"`
	BlockedDomains  []string                        `json:"blocked_domains"`
	RewriteRules    []config.PolicyRewriteRule      `json:"rewrite_rules"`
	LoadBalancers   []config.PolicyLoadBalancerRule `json:"load_balancers"`
	RuntimeApplied  bool                            `json:"runtime_applied"`
	RequiresRestart bool                            `json:"requires_restart"`
}

type pluginState struct {
	Name        string                `json:"name"`
	Enabled     bool                  `json:"enabled"`
	Description string                `json:"description"`
	Config      map[string]any        `json:"config"`
	Fields      []plugins.ConfigField `json:"fields"`
}

type pluginUpdateRequest struct {
	Config map[string]any `json:"config"`
}

type statusMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// New creates a new admin server.
func New(cfg *config.Config, m *metrics.Metrics, r ControlResolver, h *hosts.HostsPlugin, ab *adblock.AdBlockPlugin, pm *plugins.PluginManager, policyUpdater PolicyUpdater) *Server {
	username := cfg.AdminUsername
	password := cfg.AdminPassword
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	return &Server{
		addr:          cfg.AdminAddr,
		metrics:       m,
		resolver:      r,
		policyUpdater: policyUpdater,
		hosts:         h,
		adblock:       ab,
		pm:            pm,
		username:      username,
		passwordHash:  hash,
		configPath:    "config.yaml",
		baseConfig:    cloneConfig(cfg),
	}
}

// Start runs the admin server.
func (s *Server) Start() {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.FileServer(http.FS(templatesFS)))

	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	mux.Handle("/api/dashboard", s.authMiddleware(http.HandlerFunc(s.handleAPIDashboard)))
	mux.Handle("/api/metrics", s.authMiddleware(http.HandlerFunc(s.handleAPIMetrics)))
	mux.Handle("/api/config", s.authMiddleware(http.HandlerFunc(s.handleAPIConfig)))
	mux.Handle("/api/hosts", s.authMiddleware(http.HandlerFunc(s.handleAPIHosts)))
	mux.Handle("/api/policy", s.authMiddleware(http.HandlerFunc(s.handleAPIPolicy)))
	mux.Handle("/api/plugins", s.authMiddleware(http.HandlerFunc(s.handleAPIPlugins)))
	mux.Handle("/api/plugins/", s.authMiddleware(http.HandlerFunc(s.handleAPIPluginUpdate)))
	mux.Handle("/api/control/reload", s.authMiddleware(http.HandlerFunc(s.handleControlReload)))
	mux.Handle("/api/control/cache/clear", s.authMiddleware(http.HandlerFunc(s.handleControlCacheClear)))

	mux.Handle("/", s.authMiddleware(http.HandlerFunc(s.handleIndex)))

	log.Printf("Starting admin server on %s", s.addr)
	if err := http.ListenAndServe(s.addr, mux); err != nil {
		log.Fatalf("Failed to start admin server: %v", err)
	}
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		isAPI := strings.HasPrefix(r.URL.Path, "/api")

		if err != nil || cookie.Value != s.sessionToken || time.Now().After(s.sessionExpiry) {
			if isAPI {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusFound)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	errorMessage := ""
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == s.username && bcrypt.CompareHashAndPassword(s.passwordHash, []byte(password)) == nil {
			token := make([]byte, 32)
			_, _ = rand.Read(token)
			s.sessionToken = base64.StdEncoding.EncodeToString(token)
			s.sessionExpiry = time.Now().Add(12 * time.Hour)

			http.SetCookie(w, &http.Cookie{
				Name:    "session_token",
				Value:   s.sessionToken,
				Expires: s.sessionExpiry,
				Path:    "/",
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		errorMessage = "Invalid username or password"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Astracat DNS | Login</title>
	<link rel="stylesheet" href="/static/css/style.css">
</head>
<body class="login-body">
	<div class="login-shell">
		<div class="login-panel">
			<div class="login-brand">Astracat DNS Control</div>
			<p class="login-copy">Performance telemetry, policy orchestration and DNS data management from one panel.</p>
			%s
			<form method="POST" action="/login" class="login-form">
				<input type="text" name="username" class="login-input" placeholder="Username" required>
				<input type="password" name="password" class="login-input" placeholder="Password" required>
				<button type="submit" class="login-btn">Sign In</button>
			</form>
		</div>
	</div>
</body>
</html>`, func() string {
		if errorMessage == "" {
			return ""
		}
		return fmt.Sprintf(`<div class="flash flash-error">%s</div>`, errorMessage)
	}())

	_, _ = w.Write([]byte(html))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessionToken = ""
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Unix(0, 0),
		Path:    "/",
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := templatesFS.ReadFile("templates/index.html")
	if err != nil {
		log.Printf("Error reading index.html: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) handleAPIDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := dashboardResponse{
		Metrics: s.metrics.SnapshotDashboard(),
		System:  summarizeConfig(s.baseConfig),
		Plugins: s.pluginStates(),
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeJSON(w, http.StatusOK, s.metrics.SnapshotDashboard())
}

func (s *Server) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, cfg, err := s.readConfigRaw()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp := configResponse{
			Raw:             raw,
			Summary:         summarizeConfig(cfg),
			RequiresRestart: false,
		}
		s.writeJSON(w, http.StatusOK, resp)
	case http.MethodPut:
		var req configUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		cfg := config.NewConfig()
		if err := yaml.Unmarshal([]byte(req.Raw), cfg); err != nil {
			http.Error(w, "Invalid YAML: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg.Normalize()

		oldCfg := cloneConfig(s.baseConfig)
		if err := s.persistConfig(cfg); err != nil {
			http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.syncRuntime(cfg)

		resp := configUpdateResponse{
			Status:          "ok",
			Message:         "Configuration saved successfully",
			Summary:         summarizeConfig(cfg),
			RequiresRestart: requiresProcessRestart(oldCfg, cfg),
		}
		s.writeJSON(w, http.StatusOK, resp)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIHosts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := cloneConfig(s.baseConfig)
		content := ""
		if data, err := os.ReadFile(cfg.HostsPath); err == nil {
			content = string(data)
		} else if !os.IsNotExist(err) {
			http.Error(w, "Failed to read hosts file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		s.writeJSON(w, http.StatusOK, hostsResponse{
			Enabled:        cfg.HostsEnabled,
			FilePath:       cfg.HostsPath,
			HostsURL:       cfg.HostsURL,
			UpdateInterval: cfg.HostsUpdateInterval.String(),
			Content:        content,
		})
	case http.MethodPut:
		var req hostsUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		cfg := cloneConfig(s.baseConfig)
		if strings.TrimSpace(req.FilePath) != "" {
			cfg.HostsPath = strings.TrimSpace(req.FilePath)
		}
		cfg.HostsURL = strings.TrimSpace(req.HostsURL)
		if strings.TrimSpace(req.UpdateInterval) != "" {
			d, err := time.ParseDuration(strings.TrimSpace(req.UpdateInterval))
			if err != nil {
				http.Error(w, "Invalid update interval: "+err.Error(), http.StatusBadRequest)
				return
			}
			cfg.HostsUpdateInterval = d
		}

		if err := os.WriteFile(cfg.HostsPath, []byte(req.Content), 0644); err != nil {
			http.Error(w, "Failed to write hosts file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := s.persistConfig(cfg); err != nil {
			http.Error(w, "Failed to save config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.syncRuntime(cfg)

		s.writeJSON(w, http.StatusOK, statusMessage{
			Status:  "ok",
			Message: "Hosts data saved and reloaded",
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := cloneConfig(s.baseConfig)
		s.writeJSON(w, http.StatusOK, policyResponse{
			Enabled:         cfg.PolicyEngineEnabled,
			BlockedDomains:  append([]string(nil), cfg.PolicyBlockedDomains...),
			RewriteRules:    append([]config.PolicyRewriteRule(nil), cfg.PolicyRewriteRules...),
			LoadBalancers:   append([]config.PolicyLoadBalancerRule(nil), cfg.PolicyLoadBalancers...),
			RuntimeApplied:  s.policyUpdater != nil,
			RequiresRestart: s.policyUpdater == nil,
		})
	case http.MethodPut:
		var req policyResponse
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		cfg := cloneConfig(s.baseConfig)
		cfg.PolicyEngineEnabled = req.Enabled
		cfg.PolicyBlockedDomains = normalizeStringSlice(req.BlockedDomains)
		cfg.PolicyRewriteRules = sanitizeRewriteRules(req.RewriteRules)
		cfg.PolicyLoadBalancers = sanitizeLoadBalancers(req.LoadBalancers)
		cfg.Normalize()

		if err := s.persistConfig(cfg); err != nil {
			http.Error(w, "Failed to save policy: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.syncRuntime(cfg)

		s.writeJSON(w, http.StatusOK, policyResponse{
			Enabled:         cfg.PolicyEngineEnabled,
			BlockedDomains:  append([]string(nil), cfg.PolicyBlockedDomains...),
			RewriteRules:    append([]config.PolicyRewriteRule(nil), cfg.PolicyRewriteRules...),
			LoadBalancers:   append([]config.PolicyLoadBalancerRule(nil), cfg.PolicyLoadBalancers...),
			RuntimeApplied:  s.policyUpdater != nil,
			RequiresRestart: s.policyUpdater == nil,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAPIPlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeJSON(w, http.StatusOK, s.pluginStates())
}

func (s *Server) handleAPIPluginUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/plugins/")
	name = strings.TrimSpace(name)
	if name == "" {
		http.Error(w, "Plugin name is required", http.StatusBadRequest)
		return
	}

	var req pluginUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	plugin := s.pm.GetPlugin(name)
	if plugin == nil {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	cfg := cloneConfig(s.baseConfig)
	if err := applyPluginConfigToConfig(cfg, plugin.Name(), req.Config); err != nil {
		http.Error(w, "Failed to update plugin config: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg.Normalize()

	if err := s.persistConfig(cfg); err != nil {
		http.Error(w, "Failed to save plugin config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.syncRuntime(cfg)

	s.writeJSON(w, http.StatusOK, pluginState{
		Name:        plugin.Name(),
		Enabled:     isPluginEnabled(cfg, plugin.Name()),
		Description: pluginDescription(plugin.Name()),
		Config:      plugin.GetConfig(),
		Fields:      plugin.GetConfigFields(),
	})
}

func (s *Server) handleControlReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.resolver != nil {
		if err := s.resolver.Reload(s.rootAnchorPath()); err != nil {
			log.Printf("Reload failed: %v", err)
			http.Error(w, "Failed to reload: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	s.writeJSON(w, http.StatusOK, statusMessage{
		Status:  "ok",
		Message: "Resolver reload completed",
	})
}

func (s *Server) handleControlCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.resolver != nil {
		if err := s.resolver.ClearCache(s.rootAnchorPath()); err != nil {
			log.Printf("Cache clear failed: %v", err)
			http.Error(w, "Failed to clear cache: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	s.writeJSON(w, http.StatusOK, statusMessage{
		Status:  "ok",
		Message: "Cache clear completed",
	})
}

func (s *Server) rootAnchorPath() string {
	if s.baseConfig != nil {
		return s.baseConfig.RootAnchorPath
	}
	return ""
}

func (s *Server) readConfigRaw() (string, *config.Config, error) {
	if data, err := os.ReadFile(s.configPath); err == nil {
		cfg := config.NewConfig()
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return "", nil, err
		}
		cfg.Normalize()
		return string(data), cfg, nil
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}

	cfg := cloneConfig(s.baseConfig)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", nil, err
	}
	return string(data), cfg, nil
}

func (s *Server) persistConfig(cfg *config.Config) error {
	if err := cfg.Save(s.configPath); err != nil {
		return err
	}
	s.baseConfig = cloneConfig(cfg)
	return nil
}

func (s *Server) syncRuntime(cfg *config.Config) {
	s.baseConfig = cloneConfig(cfg)

	if s.metrics != nil {
		s.metrics.SetTopDomainsTracking(cfg.MetricsTopDomains)
	}

	if s.hosts != nil {
		if err := s.hosts.SetConfig(map[string]any{
			"filePath": cfg.HostsPath,
			"hostsURL": cfg.HostsURL,
			"interval": cfg.HostsUpdateInterval.String(),
		}); err != nil {
			log.Printf("admin: failed to sync hosts runtime config: %v", err)
		}
	}

	if s.adblock != nil {
		if err := s.adblock.SetConfig(map[string]any{
			"blocklists":     append([]string(nil), cfg.AdblockListURLs...),
			"updateInterval": 24 * time.Hour,
		}); err != nil {
			log.Printf("admin: failed to sync adblock runtime config: %v", err)
		}
	}

	if s.pm != nil {
		if plugin := s.pm.GetPlugin("dnsdist_compat"); plugin != nil {
			if err := plugin.SetConfig(pluginConfigFromConfig(cfg, "dnsdist_compat")); err != nil {
				log.Printf("admin: failed to sync dnsdist_compat runtime config: %v", err)
			}
		}
	}

	if s.policyUpdater != nil {
		s.policyUpdater.UpdatePolicy(buildPolicyOptions(cfg))
	}
}

func (s *Server) pluginStates() []pluginState {
	if s.pm == nil {
		return nil
	}

	pluginsList := s.pm.GetPlugins()
	out := make([]pluginState, 0, len(pluginsList))
	for _, plugin := range pluginsList {
		out = append(out, pluginState{
			Name:        plugin.Name(),
			Enabled:     isPluginEnabled(s.baseConfig, plugin.Name()),
			Description: pluginDescription(plugin.Name()),
			Config:      plugin.GetConfig(),
			Fields:      plugin.GetConfigFields(),
		})
	}
	return out
}

func summarizeConfig(cfg *config.Config) configSummary {
	if cfg == nil {
		cfg = config.NewConfig()
	}

	return configSummary{
		ListenAddr:         cfg.ListenAddr,
		AdminAddr:          cfg.AdminAddr,
		MetricsAddr:        cfg.MetricsAddr,
		ResolverType:       cfg.ResolverType,
		DoTAddr:            cfg.DoTAddr,
		ODoHAddr:           cfg.ODoHAddr,
		PrometheusEnabled:  cfg.PrometheusEnabled,
		TopDomainsEnabled:  cfg.MetricsTopDomains,
		PolicyEnabled:      cfg.PolicyEngineEnabled,
		HostsEnabled:       cfg.HostsEnabled,
		AdblockEnabled:     cfg.AdblockEnabled,
		DNSDistCompat:      cfg.DNSDistCompatEnabled,
		AttackProtection:   cfg.AttackProtectionEnabled,
		CacheRAMSize:       cfg.CacheRAMSize,
		CachePath:          cfg.CachePath,
		HostsPath:          cfg.HostsPath,
		HostsURL:           cfg.HostsURL,
		MaxQPSPerIP:        cfg.MaxQPSPerIP,
		MaxGlobalInflight:  cfg.MaxGlobalInflight,
		ResolverWorkers:    cfg.ResolverWorkers,
		MetricsStoragePath: cfg.MetricsStoragePath,
	}
}

func buildPolicyOptions(cfg *config.Config) dnsproxy.ProxyPolicyOptions {
	opts := dnsproxy.ProxyPolicyOptions{
		Enabled:        cfg.PolicyEngineEnabled,
		BlockedDomains: append([]string(nil), cfg.PolicyBlockedDomains...),
		RewriteRules:   make([]dnsproxy.ProxyRewriteRule, 0, len(cfg.PolicyRewriteRules)),
		LoadBalancers:  make([]dnsproxy.ProxyLoadBalancerRule, 0, len(cfg.PolicyLoadBalancers)),
	}

	for _, rw := range cfg.PolicyRewriteRules {
		opts.RewriteRules = append(opts.RewriteRules, dnsproxy.ProxyRewriteRule{
			Domain: rw.Domain,
			Type:   rw.Type,
			Value:  rw.Value,
			TTL:    rw.TTL,
		})
	}

	for _, lb := range cfg.PolicyLoadBalancers {
		targets := make([]dnsproxy.ProxyLoadBalancerTarget, 0, len(lb.Targets))
		for _, target := range lb.Targets {
			targets = append(targets, dnsproxy.ProxyLoadBalancerTarget{
				Value:  target.Value,
				Weight: target.Weight,
			})
		}
		opts.LoadBalancers = append(opts.LoadBalancers, dnsproxy.ProxyLoadBalancerRule{
			Domain:   lb.Domain,
			Type:     lb.Type,
			Strategy: lb.Strategy,
			TTL:      lb.TTL,
			Targets:  targets,
		})
	}

	return opts
}

func applyPluginConfigToConfig(cfg *config.Config, pluginName string, values map[string]any) error {
	switch strings.ToLower(pluginName) {
	case "hosts":
		if v, ok := values["filePath"]; ok {
			cfg.HostsPath = toString(v)
		}
		if v, ok := values["hostsURL"]; ok {
			cfg.HostsURL = toString(v)
		}
		if v, ok := values["interval"]; ok {
			d, err := time.ParseDuration(toString(v))
			if err != nil {
				return err
			}
			cfg.HostsUpdateInterval = d
		}
	case "adblock":
		cfg.AdblockListURLs = normalizeStringSlice(toStringSlice(values["blocklists"]))
	case "dnsdist_compat":
		if v, ok := values["logAll"]; ok {
			cfg.DNSDistCompatLogAll = toBool(v)
		}
		if v, ok := values["bannedIPsPath"]; ok {
			cfg.DNSDistCompatBannedIPsPath = toString(v)
		}
		if v, ok := values["sniProxyIPsPath"]; ok {
			cfg.DNSDistCompatSNIProxyIPsPath = toString(v)
		}
		if v, ok := values["domainsWithSubPath"]; ok {
			cfg.DNSDistCompatDomainsWithSubPath = toString(v)
		}
		if v, ok := values["customPath"]; ok {
			cfg.DNSDistCompatCustomPath = toString(v)
		}
		if v, ok := values["domainsPath"]; ok {
			cfg.DNSDistCompatDomainsPath = toString(v)
		}
		if v, ok := values["hostsPath"]; ok {
			cfg.DNSDistCompatHostsPath = toString(v)
		}
		if v, ok := values["garbagePath"]; ok {
			cfg.DNSDistCompatGarbagePath = toString(v)
		}
		if v, ok := values["dropSuffixes"]; ok {
			cfg.DNSDistCompatDropSuffixes = normalizeStringSlice(toStringSlice(v))
		}
		if v, ok := values["lateDropSuffixes"]; ok {
			cfg.DNSDistCompatLateDropSuffixes = normalizeStringSlice(toStringSlice(v))
		}
	default:
		return fmt.Errorf("plugin %s does not have persistent admin mapping", pluginName)
	}

	return nil
}

func pluginConfigFromConfig(cfg *config.Config, pluginName string) map[string]any {
	switch strings.ToLower(pluginName) {
	case "hosts":
		return map[string]any{
			"filePath": cfg.HostsPath,
			"hostsURL": cfg.HostsURL,
			"interval": cfg.HostsUpdateInterval.String(),
		}
	case "adblock":
		return map[string]any{
			"blocklists":     append([]string(nil), cfg.AdblockListURLs...),
			"updateInterval": 24 * time.Hour,
		}
	case "dnsdist_compat":
		return map[string]any{
			"logAll":             cfg.DNSDistCompatLogAll,
			"bannedIPsPath":      cfg.DNSDistCompatBannedIPsPath,
			"sniProxyIPsPath":    cfg.DNSDistCompatSNIProxyIPsPath,
			"domainsWithSubPath": cfg.DNSDistCompatDomainsWithSubPath,
			"customPath":         cfg.DNSDistCompatCustomPath,
			"domainsPath":        cfg.DNSDistCompatDomainsPath,
			"hostsPath":          cfg.DNSDistCompatHostsPath,
			"garbagePath":        cfg.DNSDistCompatGarbagePath,
			"dropSuffixes":       append([]string(nil), cfg.DNSDistCompatDropSuffixes...),
			"lateDropSuffixes":   append([]string(nil), cfg.DNSDistCompatLateDropSuffixes...),
		}
	default:
		return nil
	}
}

func isPluginEnabled(cfg *config.Config, name string) bool {
	switch strings.ToLower(name) {
	case "hosts":
		return cfg != nil && cfg.HostsEnabled
	case "adblock":
		return cfg != nil && cfg.AdblockEnabled
	case "dnsdist_compat":
		return cfg != nil && cfg.DNSDistCompatEnabled
	default:
		return true
	}
}

func pluginDescription(name string) string {
	switch strings.ToLower(name) {
	case "hosts":
		return "Static hosts overrides with local file and remote sync support."
	case "adblock":
		return "Domain blocklists for ad, tracker and malicious zone filtering."
	case "dnsdist_compat":
		return "dnsdist-style policy emulation layer for drops, spoofing and route control."
	default:
		return "Custom DNS plugin."
	}
}

func sanitizeRewriteRules(rules []config.PolicyRewriteRule) []config.PolicyRewriteRule {
	out := make([]config.PolicyRewriteRule, 0, len(rules))
	for _, rule := range rules {
		rule.Domain = strings.TrimSpace(rule.Domain)
		rule.Type = strings.ToUpper(strings.TrimSpace(rule.Type))
		rule.Value = strings.TrimSpace(rule.Value)
		if rule.Domain == "" || rule.Type == "" || rule.Value == "" {
			continue
		}
		if rule.TTL == 0 {
			rule.TTL = 60
		}
		out = append(out, rule)
	}
	return out
}

func sanitizeLoadBalancers(rules []config.PolicyLoadBalancerRule) []config.PolicyLoadBalancerRule {
	out := make([]config.PolicyLoadBalancerRule, 0, len(rules))
	for _, rule := range rules {
		rule.Domain = strings.TrimSpace(rule.Domain)
		rule.Type = strings.ToUpper(strings.TrimSpace(rule.Type))
		rule.Strategy = strings.TrimSpace(rule.Strategy)
		if rule.Domain == "" || rule.Type == "" {
			continue
		}
		if rule.TTL == 0 {
			rule.TTL = 30
		}

		targets := make([]config.PolicyLoadBalancerTarget, 0, len(rule.Targets))
		for _, target := range rule.Targets {
			target.Value = strings.TrimSpace(target.Value)
			if target.Value == "" {
				continue
			}
			if target.Weight <= 0 {
				target.Weight = 1
			}
			targets = append(targets, target)
		}
		if len(targets) == 0 {
			continue
		}
		rule.Targets = targets
		out = append(out, rule)
	}
	return out
}

func requiresProcessRestart(oldCfg, newCfg *config.Config) bool {
	if oldCfg == nil || newCfg == nil {
		return false
	}

	return oldCfg.ListenAddr != newCfg.ListenAddr ||
		oldCfg.AdminAddr != newCfg.AdminAddr ||
		oldCfg.MetricsAddr != newCfg.MetricsAddr ||
		oldCfg.DoTAddr != newCfg.DoTAddr ||
		oldCfg.ODoHAddr != newCfg.ODoHAddr ||
		oldCfg.ResolverType != newCfg.ResolverType ||
		oldCfg.AdblockEnabled != newCfg.AdblockEnabled ||
		oldCfg.HostsEnabled != newCfg.HostsEnabled ||
		oldCfg.DNSDistCompatEnabled != newCfg.DNSDistCompatEnabled
}

func cloneConfig(src *config.Config) *config.Config {
	if src == nil {
		return config.NewConfig()
	}

	data, err := yaml.Marshal(src)
	if err != nil {
		clone := *src
		return &clone
	}

	dst := config.NewConfig()
	if err := yaml.Unmarshal(data, dst); err != nil {
		clone := *src
		return &clone
	}
	return dst
}

func normalizeStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func toString(v any) string {
	switch value := v.(type) {
	case string:
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func toBool(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}

func toStringSlice(v any) []string {
	switch value := v.(type) {
	case []string:
		return append([]string(nil), value...)
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			out = append(out, toString(item))
		}
		return out
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		splitter := "\n"
		if strings.Contains(value, ",") && !strings.Contains(value, "\n") {
			splitter = ","
		}
		parts := strings.Split(value, splitter)
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		return nil
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("admin: failed to encode JSON response: %v", err)
	}
}
