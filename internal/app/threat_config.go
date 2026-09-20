package app

import (
	"balancedns/internal/config"
	"balancedns/internal/threat"
)

// threatConfigFrom converts the decoupled config.ThreatConfig (as parsed from
// the Lua config file) into the internal/threat.Config consumed by the
// subsystem. Category/confidence values are mapped directly; unknown values fall
// back to safe defaults inside the threat package.
func threatConfigFrom(c *config.ThreatConfig) *threat.Config {
	if c == nil {
		return threat.DefaultConfig()
	}
	out := threat.DefaultConfig()
	out.Enabled = c.Enabled
	out.DefaultAction = c.DefaultAction
	out.FailMode = c.FailMode
	out.UpdateIntervalSeconds = c.UpdateIntervalSeconds
	out.RequestTimeoutMS = c.RequestTimeoutMS
	out.MaxFeedBytes = c.MaxFeedBytes
	out.MaxDomains = c.MaxDomains
	out.RetryCount = c.RetryCount
	out.BackoffSeconds = c.BackoffSeconds
	out.DiskCacheDir = c.DiskCacheDir
	out.AllowlistFile = c.AllowlistFile
	out.CustomBlocklistFile = c.CustomBlocklistFile
	out.Reputation.MinimumSources = c.MinimumSources
	out.Reputation.BlockHighConfidence = c.BlockHighConfidence
	out.Reputation.BlockMediumConfidence = c.BlockMediumConfidence

	out.Feeds = make([]threat.FeedConfig, 0, len(c.Feeds))
	for _, f := range c.Feeds {
		out.Feeds = append(out.Feeds, threat.FeedConfig{
			Name:        f.Name,
			URL:         f.URL,
			Format:      f.Format,
			Confidence:  f.Confidence,
			Category:    f.Category,
			APIKey:      f.APIKey,
			MinEntries:  f.MinEntries,
			MaxChangePct: f.MaxChangePct,
			Enabled:     f.Enabled,
		})
	}
	// Always apply defaults again (normalizes action/fail-mode/feeds flags).
	out.ApplyDefaults()
	return out
}
