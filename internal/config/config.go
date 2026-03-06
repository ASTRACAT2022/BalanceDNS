package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type PolicyRewriteRule struct {
	Domain string `yaml:"domain"`
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
	TTL    uint32 `yaml:"ttl"`
}

type PolicyLoadBalancerTarget struct {
	Value  string `yaml:"value"`
	Weight int    `yaml:"weight"`
}

type PolicyLoadBalancerRule struct {
	Domain   string                     `yaml:"domain"`
	Type     string                     `yaml:"type"`
	Strategy string                     `yaml:"strategy"`
	TTL      uint32                     `yaml:"ttl"`
	Targets  []PolicyLoadBalancerTarget `yaml:"targets"`
}

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr          string        `yaml:"listen_addr"`
	MetricsAddr         string        `yaml:"metrics_addr"`
	PrometheusEnabled   bool          `yaml:"prometheus_enabled"`
	PrometheusNamespace string        `yaml:"prometheus_namespace"`
	UpstreamTimeout     time.Duration `yaml:"upstream_timeout"`
	RequestTimeout      time.Duration `yaml:"request_timeout"`

	// TLS Settings (DoT/DoH)
	DoTAddr string `yaml:"dot_addr"`
	// DoHAddr removed
	ODoHAddr      string `yaml:"odoh_addr"`
	LegacyDoHAddr string `yaml:"doh_addr"`  // backward-compatible alias
	CertFile      string `yaml:"cert_file"` // File path
	KeyFile       string `yaml:"key_file"`  // File path
	// Allow loading from Environment Variables as content (base64 or raw string)
	CertContent string `yaml:"-"`
	KeyContent  string `yaml:"-"`

	MaxWorkers           int           `yaml:"max_workers"`
	CacheSize            int           `yaml:"cache_size"`
	MessageCacheSize     int           `yaml:"message_cache_size"`
	RRsetCacheSize       int           `yaml:"rrset_cache_size"`
	CacheMaxTTL          time.Duration `yaml:"cache_max_ttl"`
	CacheMinTTL          time.Duration `yaml:"cache_min_ttl"`
	StaleWhileRevalidate time.Duration `yaml:"stale_while_revalidate"`
	CachePath            string        `yaml:"cache_path"`
	CacheRAMSize         int           `yaml:"cache_ram_size"`  // MB
	CacheDiskSize        int           `yaml:"cache_disk_size"` // MB (Guideline)
	ResolverType         string        `yaml:"resolver_type"`   // "unbound" or "knot"

	// Attack protection / security hardening.
	AttackProtectionEnabled bool `yaml:"attack_protection_enabled"`
	MaxGlobalInflight       int  `yaml:"max_global_inflight"`
	MaxQPSPerIP             int  `yaml:"max_qps_per_ip"`
	RateLimitBurstPerIP     int  `yaml:"rate_limit_burst_per_ip"`
	MaxConcurrentPerIP      int  `yaml:"max_concurrent_per_ip"`
	MaxQuestionsPerRequest  int  `yaml:"max_questions_per_request"`
	MaxQNameLength          int  `yaml:"max_qname_length"`
	DropANYQueries          bool `yaml:"drop_any_queries"`

	// Flexible policy engine (block/rewrite/load-balancing).
	PolicyEngineEnabled  bool                     `yaml:"policy_engine_enabled"`
	PolicyBlockedDomains []string                 `yaml:"policy_blocked_domains"`
	PolicyRewriteRules   []PolicyRewriteRule      `yaml:"policy_rewrite_rules"`
	PolicyLoadBalancers  []PolicyLoadBalancerRule `yaml:"policy_load_balancers"`

	// Hosts file plugin settings
	HostsEnabled        bool          `yaml:"hosts_enabled"`
	HostsPath           string        `yaml:"hosts_path"`
	HostsURL            string        `yaml:"hosts_url"`
	HostsUpdateInterval time.Duration `yaml:"hosts_update_interval"`

	// AdBlock plugin settings
	AdblockEnabled  bool     `yaml:"adblock_enabled"`
	AdblockListURLs []string `yaml:"adblock_list_urls"`

	// dnsdist compatibility policy layer
	DNSDistCompatEnabled            bool     `yaml:"dnsdist_compat_enabled"`
	DNSDistCompatLogAll             bool     `yaml:"dnsdist_compat_log_all"`
	DNSDistCompatBannedIPsPath      string   `yaml:"dnsdist_compat_banned_ips_path"`
	DNSDistCompatSNIProxyIPsPath    string   `yaml:"dnsdist_compat_sni_proxy_ips_path"`
	DNSDistCompatDomainsWithSubPath string   `yaml:"dnsdist_compat_domains_with_subdomains_path"`
	DNSDistCompatCustomPath         string   `yaml:"dnsdist_compat_custom_path"`
	DNSDistCompatDomainsPath        string   `yaml:"dnsdist_compat_domains_path"`
	DNSDistCompatHostsPath          string   `yaml:"dnsdist_compat_hosts_path"`
	DNSDistCompatGarbagePath        string   `yaml:"dnsdist_compat_garbage_path"`
	DNSDistCompatDropSuffixes       []string `yaml:"dnsdist_compat_drop_suffixes"`
	DNSDistCompatLateDropSuffixes   []string `yaml:"dnsdist_compat_late_drop_suffixes"`

	// Admin panel settings
	AdminAddr     string `yaml:"admin_addr"`
	AdminUsername string `yaml:"admin_username"`
	AdminPassword string `yaml:"admin_password"`

	// Metrics storage settings
	// Metrics storage settings
	MetricsStoragePath string `yaml:"metrics_storage_path"`

	// Unbound settings
	RootAnchorPath        string `yaml:"root_anchor_path"`
	ResolverWorkers       int    `yaml:"resolver_workers"`
	UnboundMsgCacheSize   string `yaml:"unbound_msg_cache_size"`
	UnboundRRsetCacheSize string `yaml:"unbound_rrset_cache_size"`
	UnboundKeyCacheSize   string `yaml:"unbound_key_cache_size"`
	UnboundPrefetch       bool   `yaml:"unbound_prefetch"`
	UnboundServeExpired   bool   `yaml:"unbound_serve_expired"`
	UnboundDisableCache   bool   `yaml:"unbound_disable_cache"`

	// Built-in recursor settings
	RecursorRootServers  []string      `yaml:"recursor_root_servers"`
	RecursorCacheEntries int           `yaml:"recursor_cache_entries"`
	RecursorCacheMinTTL  time.Duration `yaml:"recursor_cache_min_ttl"`
	RecursorCacheMaxTTL  time.Duration `yaml:"recursor_cache_max_ttl"`
	DNSSECValidate       bool          `yaml:"dnssec_validate"`
	DNSSECFailClosed     bool          `yaml:"dnssec_fail_closed"`
	DNSSECTrustAnchors   []string      `yaml:"dnssec_trust_anchors"`

	// ACME / Let's Encrypt settings
	AcmeEnabled  bool     `yaml:"acme_enabled"`
	AcmeEmail    string   `yaml:"acme_email"`
	AcmeDomains  []string `yaml:"acme_domains"`
	AcmeCacheDir string   `yaml:"acme_cache_dir"`
}

// NewConfig returns a new Config with default values.
func NewConfig() *Config {
	return &Config{
		ListenAddr:                      "0.0.0.0:5053",
		MetricsAddr:                     "0.0.0.0:9090",
		PrometheusEnabled:               true,
		PrometheusNamespace:             "dns_resolver",
		UpstreamTimeout:                 5 * time.Second,
		RequestTimeout:                  5 * time.Second,
		MaxWorkers:                      10,
		CacheMaxTTL:                     3600 * time.Second,
		CacheMinTTL:                     60 * time.Second,
		StaleWhileRevalidate:            1 * time.Minute,
		CachePath:                       "cache.db",
		CacheRAMSize:                    30,     // 30MB L1
		CacheDiskSize:                   1024,   // 1GB L2 (Concept)
		ResolverType:                    "knot", // Default to Knot resolver
		AttackProtectionEnabled:         true,
		MaxGlobalInflight:               4096,
		MaxQPSPerIP:                     300,
		RateLimitBurstPerIP:             600,
		MaxConcurrentPerIP:              200,
		MaxQuestionsPerRequest:          1,
		MaxQNameLength:                  253,
		DropANYQueries:                  true,
		PolicyEngineEnabled:             true,
		PolicyBlockedDomains:            []string{},
		PolicyRewriteRules:              []PolicyRewriteRule{},
		PolicyLoadBalancers:             []PolicyLoadBalancerRule{},
		HostsEnabled:                    true,
		HostsPath:                       "hosts",
		HostsURL:                        "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/bypass",
		HostsUpdateInterval:             1 * time.Hour,
		AdblockEnabled:                  true,
		AdblockListURLs:                 []string{"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
		DNSDistCompatEnabled:            false,
		DNSDistCompatLogAll:             false,
		DNSDistCompatBannedIPsPath:      "/etc/dnsdist/banned_ips.txt",
		DNSDistCompatSNIProxyIPsPath:    "/etc/dnsdist/sni_proxy_ips.txt",
		DNSDistCompatDomainsWithSubPath: "/etc/dnsdist/domains_with_subdomains.txt",
		DNSDistCompatCustomPath:         "/etc/dnsdist/custom.txt",
		DNSDistCompatDomainsPath:        "/etc/dnsdist/domains.txt",
		DNSDistCompatHostsPath:          "/etc/dnsdist/hosts.txt",
		DNSDistCompatGarbagePath:        "/etc/dnsdist/garbage.txt",
		DNSDistCompatDropSuffixes:       []string{"dhitc.com", "whoami.akamai.net"},
		DNSDistCompatLateDropSuffixes: []string{
			"googlesyndication.com",
			"adcolony.com",
			"hotjar.com",
			"mouseflow.com",
			"freshmarketer.com",
			"luckyorange.com",
			"bugsnag.com",
			"samsungads.com",
			"doubleclick.net",
			"media.net",
			"sentry.com",
			"sentry.io",
		},
		AdminAddr:             "",
		AdminUsername:         "",
		AdminPassword:         "",
		MetricsStoragePath:    "/tmp/dns_metrics.json",
		DoTAddr:               "", // Disabled by default
		ODoHAddr:              "", // Disabled by default
		LegacyDoHAddr:         "",
		CertFile:              "",
		KeyFile:               "",
		CertContent:           "",
		KeyContent:            "",
		RootAnchorPath:        "/var/lib/unbound/root.key",
		ResolverWorkers:       0, // auto
		UnboundMsgCacheSize:   "64m",
		UnboundRRsetCacheSize: "128m",
		UnboundKeyCacheSize:   "64m",
		UnboundPrefetch:       true,
		UnboundServeExpired:   true,
		UnboundDisableCache:   false,
		RecursorRootServers:   []string{},
		RecursorCacheEntries:  200000,
		RecursorCacheMinTTL:   5 * time.Second,
		RecursorCacheMaxTTL:   30 * time.Minute,
		DNSSECValidate:        true,
		DNSSECFailClosed:      true,
		DNSSECTrustAnchors:    []string{},
		AcmeEnabled:           false,
		AcmeCacheDir:          "certs-cache",
	}
}

// LoadFromEnv loads configuration from environment variables, overriding existing values.
func (c *Config) LoadFromEnv() {
	if v := os.Getenv("ACME_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.AcmeEnabled = b
		}
	}
	if v := os.Getenv("ACME_EMAIL"); v != "" {
		c.AcmeEmail = v
	}
	if v := os.Getenv("ACME_DOMAINS"); v != "" {
		// Comma separated list
		c.AcmeDomains = strings.Split(v, ",")
	}
	if v := os.Getenv("ACME_CACHE_DIR"); v != "" {
		c.AcmeCacheDir = v
	}
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("METRICS_ADDR"); v != "" {
		c.MetricsAddr = v
	}
	if v := os.Getenv("PROMETHEUS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.PrometheusEnabled = b
		}
	}
	if v := os.Getenv("PROMETHEUS_NAMESPACE"); v != "" {
		c.PrometheusNamespace = v
	}
	if v := os.Getenv("ADMIN_ADDR"); v != "" {
		c.AdminAddr = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.DNSDistCompatEnabled = b
		}
	}
	if v := os.Getenv("DNSDIST_COMPAT_LOG_ALL"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.DNSDistCompatLogAll = b
		}
	}
	if v := os.Getenv("DNSDIST_COMPAT_BANNED_IPS_PATH"); v != "" {
		c.DNSDistCompatBannedIPsPath = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_SNI_PROXY_IPS_PATH"); v != "" {
		c.DNSDistCompatSNIProxyIPsPath = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_DOMAINS_WITH_SUBDOMAINS_PATH"); v != "" {
		c.DNSDistCompatDomainsWithSubPath = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_CUSTOM_PATH"); v != "" {
		c.DNSDistCompatCustomPath = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_DOMAINS_PATH"); v != "" {
		c.DNSDistCompatDomainsPath = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_HOSTS_PATH"); v != "" {
		c.DNSDistCompatHostsPath = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_GARBAGE_PATH"); v != "" {
		c.DNSDistCompatGarbagePath = v
	}
	if v := os.Getenv("DNSDIST_COMPAT_DROP_SUFFIXES"); v != "" {
		items := strings.Split(v, ",")
		parsed := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				parsed = append(parsed, item)
			}
		}
		c.DNSDistCompatDropSuffixes = parsed
	}
	if v := os.Getenv("DNSDIST_COMPAT_LATE_DROP_SUFFIXES"); v != "" {
		items := strings.Split(v, ",")
		parsed := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				parsed = append(parsed, item)
			}
		}
		c.DNSDistCompatLateDropSuffixes = parsed
	}
	if v := os.Getenv("ADMIN_USERNAME"); v != "" {
		c.AdminUsername = v
	}
	if v := os.Getenv("ADMIN_PASSWORD"); v != "" {
		c.AdminPassword = v
	}
	if v := os.Getenv("DOH_ADDR"); v != "" {
		c.ODoHAddr = v // Map DOH_ADDR to ODoHAddr as it seems to be the active one
	}
	if v := os.Getenv("ODOH_ADDR"); v != "" {
		c.ODoHAddr = v
	}
	if v := os.Getenv("DOT_ADDR"); v != "" {
		c.DoTAddr = v
	}
	if v := os.Getenv("SSL_CERT_CONTENT"); v != "" {
		c.CertContent = v
	}
	if v := os.Getenv("SSL_KEY_CONTENT"); v != "" {
		c.KeyContent = v
	}
	if v := os.Getenv("ROOT_ANCHOR_PATH"); v != "" {
		c.RootAnchorPath = v
	}
	if v := os.Getenv("UNBOUND_MSG_CACHE_SIZE"); v != "" {
		c.UnboundMsgCacheSize = v
	}
	if v := os.Getenv("UNBOUND_RRSET_CACHE_SIZE"); v != "" {
		c.UnboundRRsetCacheSize = v
	}
	if v := os.Getenv("UNBOUND_KEY_CACHE_SIZE"); v != "" {
		c.UnboundKeyCacheSize = v
	}
	if v := os.Getenv("METRICS_STORAGE_PATH"); v != "" {
		c.MetricsStoragePath = v
	}
	if v := os.Getenv("CACHE_PATH"); v != "" {
		c.CachePath = v
	}
	if v := os.Getenv("RESOLVER_TYPE"); v != "" {
		c.ResolverType = v
	}
	if v := os.Getenv("ATTACK_PROTECTION_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.AttackProtectionEnabled = b
		}
	}
	if v := os.Getenv("DROP_ANY_QUERIES"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.DropANYQueries = b
		}
	}
	if v := os.Getenv("POLICY_ENGINE_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.PolicyEngineEnabled = b
		}
	}
	if v := os.Getenv("POLICY_BLOCKED_DOMAINS"); v != "" {
		items := strings.Split(v, ",")
		parsed := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				parsed = append(parsed, item)
			}
		}
		c.PolicyBlockedDomains = parsed
	}

	// Integers
	if v := os.Getenv("MAX_WORKERS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.MaxWorkers = i
		}
	}
	if v := os.Getenv("CACHE_SIZE"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.CacheSize = i
		}
	}
	if v := os.Getenv("CACHE_RAM_SIZE"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.CacheRAMSize = i
		}
	}
	if v := os.Getenv("MAX_GLOBAL_INFLIGHT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.MaxGlobalInflight = i
		}
	}
	if v := os.Getenv("MAX_QPS_PER_IP"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.MaxQPSPerIP = i
		}
	}
	if v := os.Getenv("RATE_LIMIT_BURST_PER_IP"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.RateLimitBurstPerIP = i
		}
	}
	if v := os.Getenv("MAX_CONCURRENT_PER_IP"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.MaxConcurrentPerIP = i
		}
	}
	if v := os.Getenv("MAX_QUESTIONS_PER_REQUEST"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.MaxQuestionsPerRequest = i
		}
	}
	if v := os.Getenv("MAX_QNAME_LENGTH"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.MaxQNameLength = i
		}
	}
	if v := os.Getenv("RESOLVER_WORKERS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.ResolverWorkers = i
		}
	}
	if v := os.Getenv("RECURSOR_CACHE_ENTRIES"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.RecursorCacheEntries = i
		}
	}
	if v := os.Getenv("RECURSOR_ROOT_SERVERS"); v != "" {
		items := strings.Split(v, ",")
		servers := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				servers = append(servers, item)
			}
		}
		c.RecursorRootServers = servers
	}
	if v := os.Getenv("RECURSOR_CACHE_MIN_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.RecursorCacheMinTTL = d
		}
	}
	if v := os.Getenv("RECURSOR_CACHE_MAX_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.RecursorCacheMaxTTL = d
		}
	}
	if v := os.Getenv("DNSSEC_VALIDATE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.DNSSECValidate = b
		}
	}
	if v := os.Getenv("DNSSEC_FAIL_CLOSED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.DNSSECFailClosed = b
		}
	}
	if v := os.Getenv("DNSSEC_TRUST_ANCHORS"); v != "" {
		items := strings.Split(v, ",")
		anchors := make([]string, 0, len(items))
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				anchors = append(anchors, item)
			}
		}
		c.DNSSECTrustAnchors = anchors
	}

	// Bools
	if v := os.Getenv("ADBLOCK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.AdblockEnabled = b
		}
	}
	if v := os.Getenv("HOSTS_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.HostsEnabled = b
		}
	}
	if v := os.Getenv("UNBOUND_PREFETCH"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.UnboundPrefetch = b
		}
	}
	if v := os.Getenv("UNBOUND_SERVE_EXPIRED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.UnboundServeExpired = b
		}
	}
	if v := os.Getenv("UNBOUND_DISABLE_CACHE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.UnboundDisableCache = b
		}
	}
}

// Normalize applies compatibility aliases and defaults after loading config.
func (c *Config) Normalize() {
	if c.ODoHAddr == "" && c.LegacyDoHAddr != "" {
		c.ODoHAddr = c.LegacyDoHAddr
	}
	c.DNSDistCompatDropSuffixes = normalizeDomainLikeList(c.DNSDistCompatDropSuffixes)
	c.DNSDistCompatLateDropSuffixes = normalizeDomainLikeList(c.DNSDistCompatLateDropSuffixes)
}

func normalizeDomainLikeList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		item = strings.TrimSuffix(item, ".")
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// Save saves the configuration to a YAML file.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
