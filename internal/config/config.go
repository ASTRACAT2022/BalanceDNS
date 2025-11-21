package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr           string
	MetricsAddr          string
	PrometheusEnabled    bool
	PrometheusNamespace  string
	UpstreamTimeout      time.Duration
	RequestTimeout       time.Duration
	MaxWorkers           int
	CacheSize            int
	MessageCacheSize     int
	RRsetCacheSize       int
	CacheMaxTTL          time.Duration
	CacheMinTTL          time.Duration
	StaleWhileRevalidate time.Duration
	LMDBPath             string
	ResolverType         string // "unbound" or "knot"

	// Hosts file plugin settings
	HostsEnabled bool
	HostsPath    string

	// AdBlock plugin settings
	AdblockEnabled  bool
	AdblockListURLs []string

	// Rate limit plugin settings
	RateLimitEnabled bool
	RateLimitQPS     int
	RateLimitBurst   int

	// Admin panel settings
	AdminAddr string

	// Metrics storage settings
	MetricsStoragePath string
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
		CacheSize:            5000,
		MessageCacheSize:     5000,
		RRsetCacheSize:       5000,
		CacheMaxTTL:          3600 * time.Second,
		CacheMinTTL:          60 * time.Second,
		StaleWhileRevalidate: 1 * time.Minute,
		LMDBPath:             "/tmp/dns_cache.lmdb",
		ResolverType:         "knot", // Default to Knot resolver
		HostsEnabled:         true,
		HostsPath:            "hosts",
		AdblockEnabled:       true,
		AdblockListURLs:      []string{"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
		RateLimitEnabled:     true,
		RateLimitQPS:         50,
		RateLimitBurst:       20,
		AdminAddr:            "0.0.0.0:8080",
		MetricsStoragePath:   "/tmp/dns_metrics.json",
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
