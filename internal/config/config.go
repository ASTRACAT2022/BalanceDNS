package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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
	ODoHAddr string `yaml:"odoh_addr"`
	CertFile string `yaml:"cert_file"` // File path
	KeyFile  string `yaml:"key_file"`  // File path
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

	// Hosts file plugin settings
	HostsEnabled        bool          `yaml:"hosts_enabled"`
	HostsPath           string        `yaml:"hosts_path"`
	HostsURL            string        `yaml:"hosts_url"`
	HostsUpdateInterval time.Duration `yaml:"hosts_update_interval"`

	// AdBlock plugin settings
	AdblockEnabled  bool     `yaml:"adblock_enabled"`
	AdblockListURLs []string `yaml:"adblock_list_urls"`

	// Admin panel settings
	AdminAddr string `yaml:"admin_addr"`

	// Metrics storage settings
	// Metrics storage settings
	MetricsStoragePath string `yaml:"metrics_storage_path"`

	// Unbound settings
	RootAnchorPath string `yaml:"root_anchor_path"`

	// ACME / Let's Encrypt settings
	AcmeEnabled  bool     `yaml:"acme_enabled"`
	AcmeEmail    string   `yaml:"acme_email"`
	AcmeDomains  []string `yaml:"acme_domains"`
	AcmeCacheDir string   `yaml:"acme_cache_dir"`

	// Cluster settings
	ClusterRole         string        `yaml:"cluster_role"`          // "standalone", "admin", or "node"
	ClusterAdminURL     string        `yaml:"cluster_admin_url"`     // Base URL to admin server (e.g. http://10.0.0.1:8080)
	ClusterToken        string        `yaml:"cluster_token"`         // Shared secret for node/admin sync
	ClusterSyncInterval time.Duration `yaml:"cluster_sync_interval"` // How often nodes refresh config/certs
}

// NewConfig returns a new Config with default values.
func NewConfig() *Config {
	return &Config{
		ListenAddr:           "0.0.0.0:5053",
		MetricsAddr:          "0.0.0.0:9090",
		PrometheusEnabled:    false,
		PrometheusNamespace:  "dns_resolver",
		UpstreamTimeout:      5 * time.Second,
		RequestTimeout:       5 * time.Second,
		MaxWorkers:           10,
		CacheMaxTTL:          3600 * time.Second,
		CacheMinTTL:          60 * time.Second,
		StaleWhileRevalidate: 1 * time.Minute,
		CachePath:            "cache.db",
		CacheRAMSize:         30,     // 30MB L1
		CacheDiskSize:        1024,   // 1GB L2 (Concept)
		ResolverType:         "knot", // Default to Knot resolver
		HostsEnabled:         true,
		HostsPath:            "hosts",
		HostsURL:             "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/bypass",
		HostsUpdateInterval:  1 * time.Hour,
		AdblockEnabled:       true,
		AdblockListURLs:      []string{"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
		AdminAddr:            "0.0.0.0:8080",
		MetricsStoragePath:   "/tmp/dns_metrics.json",
		DoTAddr:              "", // Disabled by default
		ODoHAddr:             "", // Disabled by default
		CertFile:             "",
		KeyFile:              "",
		CertContent:          "",
		KeyContent:           "",
		RootAnchorPath:       "/var/lib/unbound/root.key",
		AcmeEnabled:          false,
		AcmeCacheDir:         "certs-cache",
		ClusterRole:          "standalone",
		ClusterAdminURL:      "",
		ClusterToken:         "",
		ClusterSyncInterval:  30 * time.Second,
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
	if v := os.Getenv("CLUSTER_ROLE"); v != "" {
		c.ClusterRole = v
	}
	if v := os.Getenv("CLUSTER_ADMIN_URL"); v != "" {
		c.ClusterAdminURL = v
	}
	if v := os.Getenv("CLUSTER_TOKEN"); v != "" {
		c.ClusterToken = v
	}
	if v := os.Getenv("CLUSTER_SYNC_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.ClusterSyncInterval = d
		}
	}

	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("METRICS_ADDR"); v != "" {
		c.MetricsAddr = v
	}
	if v := os.Getenv("ADMIN_ADDR"); v != "" {
		c.AdminAddr = v
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
	if v := os.Getenv("METRICS_STORAGE_PATH"); v != "" {
		c.MetricsStoragePath = v
	}
	if v := os.Getenv("CACHE_PATH"); v != "" {
		c.CachePath = v
	}
	if v := os.Getenv("RESOLVER_TYPE"); v != "" {
		c.ResolverType = v
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
}

// Save saves the configuration to a YAML file.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
