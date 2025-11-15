package config

import (
	"io/ioutil"
	"time"

	"gopkg.in/yaml.v2"
)

// UnboundConfig holds the configuration for the Unbound resolver.
type UnboundConfig struct {
	NumThreads        int    `yaml:"num-threads"`
	SoReuseport       bool   `yaml:"so-reuseport"`
	Prefetch          bool   `yaml:"prefetch"`
	Chroot            string `yaml:"chroot"`
	ValPermissiveMode bool   `yaml:"val-permissive-mode"`
}

// Config holds the configuration for the DNS resolver.
type Config struct {
	ListenAddr           string        `yaml:"listen_addr"`
	MetricsAddr          string        `yaml:"metrics_addr"`
	PrometheusEnabled    bool          `yaml:"prometheus_enabled"`
	PrometheusNamespace  string        `yaml:"prometheus_namespace"`
	UpstreamTimeout      time.Duration `yaml:"upstream_timeout"`
	RequestTimeout       time.Duration `yaml:"request_timeout"`
	MaxWorkers           int           `yaml:"max_workers"`
	CacheSize            int           `yaml:"cache_size"`
	MessageCacheSize     string        `yaml:"message_cache_size"`
	RRsetCacheSize       string        `yaml:"rrset_cache_size"`
	CacheMaxTTL          time.Duration `yaml:"cache_max_ttl"`
	CacheMinTTL          time.Duration `yaml:"cache_min_ttl"`
	StaleWhileRevalidate time.Duration `yaml:"stale_while_revalidate"`
	LMDBPath             string        `yaml:"lmdb_path"`
	ResolverType         string        `yaml:"resolver_type"`
	LogLevel             string        `yaml:"log_level"`
	Unbound              UnboundConfig `yaml:"unbound"`
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
		MessageCacheSize:     "4m",
		RRsetCacheSize:       "8m",
		CacheMaxTTL:          3600 * time.Second,
		CacheMinTTL:          60 * time.Second,
		StaleWhileRevalidate: 1 * time.Minute,
		LMDBPath:             "/tmp/dns_cache.lmdb",
		ResolverType:         "unbound", // Default to unbound resolver
		LogLevel:             "info",
		Unbound: UnboundConfig{
			NumThreads:        1,
			SoReuseport:       true,
			Prefetch:          false,
			Chroot:            "",
			ValPermissiveMode: true,
		},
	}
}

// LoadConfig loads the configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	cfg := NewConfig()

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
