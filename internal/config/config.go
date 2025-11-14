package config

import "time"

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
		MaxWorkers:           50, // Increased for better concurrency
		CacheSize:            10000, // Increased cache size
		MessageCacheSize:     10000,
		RRsetCacheSize:       10000,
		CacheMaxTTL:          3600 * time.Second,
		CacheMinTTL:          60 * time.Second,
		StaleWhileRevalidate: 2 * time.Minute, // Increased for better performance
		LMDBPath:             "/tmp/dns_cache.lmdb",
		ResolverType:         "godns", // Default to GoDNS resolver for better performance
	}
}
