-- ============================================================================
-- BalanceDNS — Threat Intelligence configuration example
-- ============================================================================
-- This file shows how to enable the Threat Intelligence subsystem on top of a
-- working resolver config. It is an EXAMPLE: replace upstreams, listen
-- addresses, feed URLs and file paths with your production values.
--
-- Enable procedure (zero-downtime):
--   1. Place threat_intelligence.lua where this config points to it.
--   2. Create the allowlist and custom blocklist files (can be empty).
--   3. Restart balanceDNS once. The first update runs in the background and
--      writes snapshot.json to disk_cache_dir; subsequent restarts seed from it.
--   4. On next scheduled refresh (update_interval) feeds re-pull and the
--      snapshot is swapped atomically — no request is ever answered from a
--      partially built list.
--
-- Rollback: remove the "threat" block (or set enabled=false), remove
-- plug_entries "threat-intelligence", and set block_rcode back to REFUSED or
-- remove the plugins.block_rcode line. A restart restores previous behaviour.
-- ============================================================================

return {
  listen = {
    dns = "0.0.0.0:5353",           -- EXAMPLE non-privileged port
    metrics = "0.0.0.0:9099",
    read_timeout_ms = 2500,
    write_timeout_ms = 2500,
    udp_size = 1232,
  },

  logging = {
    level = env("BALANCEDNS_LOG_LEVEL", "info"),
    log_queries = true,              -- enable to see DROP/NXDOMAIN outcomes
  },

  acl = { "0.0.0.0/0", "::/0" },

  upstreams = {
    {
      name = "global-primary",
      protocol = "udp",
      addr = "77.88.8.8:53",
      zones = { "." },
      timeout_ms = 1200,
    },
    {
      name = "global-backup",
      protocol = "udp",
      addr = "188.93.16.19:53",
      zones = { "." },
      timeout_ms = 1200,
    },
  },

  routing = {
    chain = { "blacklist", "hosts", "cache", "lua_policy", "upstream" },
  },

  cache = {
    enabled = true,
    capacity = 250000,
    min_ttl_seconds = 5,
    max_ttl_seconds = 1800,
  },

  plugins = {
    enabled = true,
    timeout_ms = 20,
    -- Block response for policy BLOCK actions (including threat blocking).
    -- "REFUSED" (legacy default) | "NXDOMAIN" | "DROP" (no response = retry).
    block_rcode = "NXDOMAIN",
    entries = {
      { name = "lua-policy", runtime = "lua", path = "../scripts/policy.lua" },
      -- Threat Intelligence policy. Order matters: put it AFTER any local
      -- rewrite/local-data policy and BEFORE the final FORWARD upstream stage.
      { name = "threat-intelligence", runtime = "lua", path = "../scripts/threat_intelligence.lua" },
    },
  },

  -- ------------------------------------------------------------------
  -- Threat Intelligence subsystem
  -- ------------------------------------------------------------------
  threat = {
    enabled = true,

    -- Response to a blocked query: NXDOMAIN (default) | REFUSED | DROP.
    -- Note: this mirrors plugins.block_rcode; set one consistently.
    default_action = "NXDOMAIN",

    -- "open"  = on subsystem error the query resolves normally (default, safest).
    -- "closed"= on subsystem error the query is blocked (use with care).
    fail_mode = "open",

    -- Feed refresh cadence and network hardening.
    update_interval = 14400,          -- seconds (4h)
    request_timeout_ms = 15000,
    max_feed_bytes = 67108864,        -- 64 MiB hard cap per feed
    max_domains = 0,                  -- 0 = unlimited; set to hard ceiling if large

    -- Retry/backoff for failed update cycles (old snapshot stays active).
    retry_count = 3,
    backoff_seconds = 30,

    -- Persisted "last good" snapshot; restart seeds from this for instant DNS.
    disk_cache_dir = "/var/lib/balancedns/threat-intelligence",

    -- Paths to the allowlist and custom ASTRACAT blocklist (one domain/line).
    allowlist_file = "/etc/balancedns/threat-allowlist.txt",
    custom_blocklist_file = "/etc/balancedns/threat-custom-blocklist.txt",

    -- Reputation thresholds.
    minimum_sources = 2,              -- block (non-custom) domains seen in >=2 feeds
    block_high_confidence = true,     -- block single high-confidence feed hits
    block_medium_confidence = false,   -- medium confidence only via minimum_sources

    -- Enabled categories (enforcement). Unlisted categories are ignored.
    categories = {
      malware = true,
      botnet_c2 = true,
      phishing = true,
      scam = true,
      cryptomining = true,
      malicious_redirector = true,
      custom_abuse = true,
    },

    -- Threat feeds. Confidence: low|medium|high|custom.
    -- Format: domains | hosts | rpz | json.
    -- Only HTTPS URLs are allowed (SSRF-hardened).
    feeds = {
      {
        name = "astracat-c2",
        url = "https://feeds.astracat.example/c2-c2.txt",   -- REPLACE ME
        format = "domains",
        confidence = "high",
        category = "botnet_c2",
        enabled = true,
        min_entries = 10,             -- reject feeds that collapse below this
      },
      {
        name = "phishing-feed",
        url = "https://feeds.astracat.example/phishing.txt", -- REPLACE ME
        format = "domains",
        confidence = "medium",
        category = "phishing",
        enabled = true,
        min_entries = 10,
      },
    },
  },

  blacklist = {},
}
