package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr         string          `yaml:"listen_addr"`
	MetricsAddr        string          `yaml:"metrics_addr"`
	AdminAddr          string          `yaml:"admin_addr"`
	MetricsStoragePath string          `yaml:"metrics_storage_path"`
	Resolver           ResolverConfig  `yaml:"resolver"`
	Cache              CacheConfig     `yaml:"cache"`
	Hosts              HostsConfig     `yaml:"hosts"`
	AdBlock            AdBlockConfig   `yaml:"adblock"`
	RateLimit          RateLimitConfig `yaml:"rate_limit"`
	DoH                DoHConfig       `yaml:"doh"`
	DoT                DoTConfig       `yaml:"dot"`
}

// ResolverConfig holds settings for the resolver.
type ResolverConfig struct {
	Type            string        `yaml:"type"`
	UpstreamTimeout time.Duration `yaml:"upstream_timeout"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	MaxWorkers      int           `yaml:"max_workers"`
}

// CacheConfig holds settings for the cache.
type CacheConfig struct {
	LMDBPath             string        `yaml:"lmdb_path"`
	Size                 int           `yaml:"size"`
	MaxTTL               time.Duration `yaml:"max_ttl"`
	MinTTL               time.Duration `yaml:"min_ttl"`
	StaleWhileRevalidate time.Duration `yaml:"stale_while_revalidate"`
}

// HostsConfig holds settings for the hosts file plugin.
type HostsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// AdBlockConfig holds settings for the AdBlock plugin.
type AdBlockConfig struct {
	Enabled       bool     `yaml:"enabled"`
	BlocklistURLs []string `yaml:"blocklist_urls"`
}

// RateLimitConfig holds settings for the rate limit plugin.
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	QPS     int  `yaml:"qps"`
	Burst   int  `yaml:"burst"`
}

// DoHConfig holds settings for DNS-over-HTTPS.
type DoHConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
}

// DoTConfig holds settings for DNS-over-TLS.
type DoTConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_addr"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
}

// NewConfig returns a new Config with default values.
func NewConfig() *Config {
	return &Config{
		ListenAddr:         "0.0.0.0:5053",
		MetricsAddr:        "0.0.0.0:9090",
		AdminAddr:          "0.0.0.0:8080",
		MetricsStoragePath: "/tmp/dns_metrics.json",
		Resolver: ResolverConfig{
			Type:            "godns",
			UpstreamTimeout: 5 * time.Second,
			RequestTimeout:  5 * time.Second,
			MaxWorkers:      10,
		},
		Cache: CacheConfig{
			LMDBPath:             "/tmp/dns_cache.lmdb",
			Size:                 5000,
			MaxTTL:               3600 * time.Second,
			MinTTL:               60 * time.Second,
			StaleWhileRevalidate: 1 * time.Minute,
		},
		Hosts: HostsConfig{
			Enabled: true,
			Path:    "hosts",
		},
		AdBlock: AdBlockConfig{
			Enabled: true,
			BlocklistURLs: []string{
				"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			},
		},
		RateLimit: RateLimitConfig{
			Enabled: false,
			QPS:     100,
			Burst:   200,
		},
		DoH: DoHConfig{
			Enabled:    false,
			ListenAddr: "0.0.0.0:443",
			CertFile:   "",
			KeyFile:    "",
		},
		DoT: DoTConfig{
			Enabled:    false,
			ListenAddr: "0.0.0.0:853",
			CertFile:   "",
			KeyFile:    "",
		},
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
