package threat

import "time"

// Config is the full configuration for the Threat Intelligence subsystem.
// It is populated from the Lua config (see config.lua and the wiring in
// internal/app/server.go) and from the defaults below.
type Config struct {
	Enabled bool `json:"enabled"`

	// DefaultAction is the DNS rcode the policy uses to block: "NXDOMAIN",
	// "REFUSED", or "DROP". Default NXDOMAIN.
	DefaultAction string `json:"default_action"`

	// FailMode is "open" (default) or "closed". In "open" mode any threat
	// subsystem error fails the check open (query proceeds to normal DNS); in
	// "closed" mode a missing snapshot blocks everything. Default "open".
	FailMode string `json:"fail_mode"`

	// UpdateIntervalSeconds is how often feeds are refreshed in the background.
	UpdateIntervalSeconds int `json:"update_interval"`

	// RequestTimeoutMS bounds each feed fetch.
	RequestTimeoutMS int `json:"request_timeout_ms"`

	// MaxFeedBytes bounds the response body per feed (protects against runaway
	// downloads). Default 64 MiB.
	MaxFeedBytes int64 `json:"max_feed_bytes"`

	// MaxDomains caps total distinct domains in a compiled snapshot. 0 = no cap.
	MaxDomains int `json:"max_domains"`

	// RetryCount is the maximum consecutive failed update attempts before we
	// give up for the current cycle and keep the old snapshot.
	RetryCount int `json:"retry_count"`

	// BackoffSeconds is the base backoff between retries.
	BackoffSeconds int `json:"backoff_seconds"`

	// DiskCacheDir is where the last good snapshot is persisted so a restart
	// starts from known-good data instead of a cold empty snapshot.
	DiskCacheDir string `json:"disk_cache_dir"`

	// AllowlistFile is the path to the allowlist (one domain per line; parent
	// domains allow all subdomains).
	AllowlistFile string `json:"allowlist_file"`

	// CustomBlocklistFile is the path to the ASTRACAT custom blocklist (max
	// priority after allowlist; blocks immediately on reload).
	CustomBlocklistFile string `json:"custom_blocklist_file"`

	// Reputation controls how snapshots are built.
	Reputation ReputationConfig `json:"reputation"`

	// Categories enable/disable enforcement per category.
	Categories map[Category]bool `json:"categories"`

	// Feeds is the list of configured threat feeds.
	Feeds []FeedConfig `json:"feeds"`
}

// ReputationConfig configures the IOC scoring thresholds.
type ReputationConfig struct {
	// MinimumSources is how many distinct (non-custom) feeds a domain must be
	// seen in before it is blocked (when it would otherwise lack high
	// confidence). Default 2.
	MinimumSources int `json:"minimum_sources"`

	// BlockHighConfidence blocks any high- or custom-confidence IOC regardless
	// of source count. Default true.
	BlockHighConfidence bool `json:"block_high_confidence"`

	// BlockMediumConfidence blocks medium-confidence IOCs from >=2 sources.
	// Default false (observe-only unless MinimumSources reached or high).
	BlockMediumConfidence bool `json:"block_medium_confidence"`
}

// FeedConfig describes one threat feed source.
type FeedConfig struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Format     string `json:"format"`          // domains | hosts | rpz | json
	Confidence string `json:"confidence"`       // low|medium|high|custom
	Category   string `json:"category"`         // malware|botnet_c2|...
	APIKey     string `json:"api_key,omitempty"` // optional auth header
	// MinEntries is a sanity floor: if a successful fetch yields fewer, the
	// feed is treated as broken and rejected. 0 disables the check.
	MinEntries int `json:"min_entries"`
	// MaxChangePct is a sanity ceiling on allowed change vs the previous
	// snapshot of this feed. 100+ disables. Negative means rejected.
	MaxChangePct int `json:"max_change_pct"`
	// Enabled toggles the feed without removing it from config.
	Enabled bool `json:"enabled"`
}

// ParseRcode maps a config action string to a normalized block action.
func ParseRcode(s string) string {
	switch s {
	case "", "NXDOMAIN":
		return "NXDOMAIN"
	case "REFUSED":
		return "REFUSED"
	case "DROP":
		return "DROP"
	default:
		return "NXDOMAIN"
	}
}

// ParseFailMode maps a config fail_mode string to normalized "open"/"closed".
func ParseFailMode(s string) string {
	switch s {
	case "closed":
		return "closed"
	default:
		return "open"
	}
}

// ApplyDefaults fills unset fields with safe defaults. It is idempotent.
func (c *Config) ApplyDefaults() {
	if c.DefaultAction == "" {
		c.DefaultAction = "NXDOMAIN"
	}
	if c.FailMode == "" {
		c.FailMode = "open"
	}
	if c.UpdateIntervalSeconds <= 0 {
		c.UpdateIntervalSeconds = 14400 // 4h
	}
	if c.RequestTimeoutMS <= 0 {
		c.RequestTimeoutMS = 15000
	}
	if c.MaxFeedBytes <= 0 {
		c.MaxFeedBytes = 64 << 20 // 64 MiB
	}
	if c.RetryCount <= 0 {
		c.RetryCount = 3
	}
	if c.BackoffSeconds <= 0 {
		c.BackoffSeconds = 30
	}
	if c.Reputation.MinimumSources == 0 {
		c.Reputation.MinimumSources = 2
	}
	c.Reputation.BlockHighConfidence = true
	if c.DiskCacheDir == "" {
		c.DiskCacheDir = "/var/lib/balancedns/threat-intelligence"
	}
	if c.Categories == nil {
		c.Categories = map[Category]bool{
			CategoryMalware:        true,
			CategoryBotnetC2:       true,
			CategoryPhishing:       true,
			CategoryScam:           true,
			CategoryCryptomining:   true,
			CategoryMaliciousRedir: true,
			CategoryCustomAbuse:    true,
		}
	}
}

// DefaultConfig returns a config with all defaults applied and no feeds.
func DefaultConfig() *Config {
	c := &Config{}
	c.ApplyDefaults()
	return c
}

// UpdateInterval returns the update interval as a time.Duration.
func (c *Config) UpdateInterval() time.Duration {
	return time.Duration(c.UpdateIntervalSeconds) * time.Second
}

// RequestTimeout returns the fetch timeout as a time.Duration.
func (c *Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutMS) * time.Millisecond
}
