package config

import (
	"os"
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
	DoTAddr  string `yaml:"dot_addr"`
	DoHAddr  string `yaml:"doh_addr"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	MaxWorkers           int           `yaml:"max_workers"`
	CacheSize            int           `yaml:"cache_size"`
	MessageCacheSize     int           `yaml:"message_cache_size"`
	RRsetCacheSize       int           `yaml:"rrset_cache_size"`
	CacheMaxTTL          time.Duration `yaml:"cache_max_ttl"`
	CacheMinTTL          time.Duration `yaml:"cache_min_ttl"`
	StaleWhileRevalidate time.Duration `yaml:"stale_while_revalidate"`
	CachePath            string        `yaml:"cache_path"`
	ResolverType         string        `yaml:"resolver_type"` // "unbound" or "knot"

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
		CacheSize:            1024, // 1024 MB
		MessageCacheSize:     5000,
		RRsetCacheSize:       5000,
		CacheMaxTTL:          3600 * time.Second,
		CacheMinTTL:          60 * time.Second,
		StaleWhileRevalidate: 1 * time.Minute,
		CachePath:            "cache/dns.db",
		ResolverType:         "knot", // Default to Knot resolver
		HostsEnabled:         true,
		HostsPath:            "hosts",
		HostsURL:             "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/bypass",
		HostsUpdateInterval:  1 * time.Hour,
		AdblockEnabled:       true,
		AdblockListURLs:      []string{"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
		AdminAddr:            "0.0.0.0:8080",
		MetricsStoragePath:   "/tmp/dns_metrics.json",
		DoTAddr:              "0.0.0.0:853",
		DoHAddr:              "0.0.0.0:443",
		CertFile:             "",
		KeyFile:              "",
		RootAnchorPath:       "/opt/homebrew/etc/unbound/root.key", // Default macos path for homebrew unbound
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
