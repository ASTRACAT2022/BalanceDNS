return {
  listen = {
    dns = ":53",
    metrics = ":9090",
    read_timeout_ms = 2000,
    write_timeout_ms = 2000,
    reuse_port = true,
    reuse_addr = true,
    udp_size = 1232,
  },

  logging = {
    level = "info",
    log_queries = true,
  },

  upstreams = {
    {
      name = "global-doh",
      protocol = "doh",
      doh_url = "https://dns.google/dns-query",
      zones = { "." },
      timeout_ms = 1500,
    },
    {
      name = "global-dot-backup",
      protocol = "dot",
      addr = "1.1.1.1:853",
      tls_server_name = "cloudflare-dns.com",
      zones = { "." },
      timeout_ms = 1500,
    },
  },

  routing = {
    chain = { "blacklist", "cache", "lua_policy", "upstream" },
  },

  cache = {
    enabled = true,
    capacity = 100000,
    min_ttl_seconds = 5,
    max_ttl_seconds = 600,
  },

  plugins = {
    enabled = true,
    timeout_ms = 20,
    entries = {
      {
        name = "lua-policy",
        runtime = "lua",
        path = "/app/scripts/policy.lua",
      },
    },
  },

  blacklist = {
    domains = {},
  },

  control = {
    restart_backoff_ms = 200,
    restart_max_backoff_ms = 5000,
    max_consecutive_failure = 0,
    min_stable_run_ms = 10000,
  },
}
