return {
  listen = {
    dns = "0.0.0.0:53",
    dot = "0.0.0.0:853",
    doh = "0.0.0.0:5443",
    doh_path = "/dns-query",
    tls_cert_file = "/certs/dns.astracat.ru/fullchain.pem",
    tls_key_file = "/certs/dns.astracat.ru/privkey.pem",
    metrics = "0.0.0.0:9099",
    read_timeout_ms = 2500,
    write_timeout_ms = 2500,
    reuse_port = true,
    reuse_addr = true,
    udp_size = 1232,
  },

  logging = {
    level = env("BALANCEDNS_LOG_LEVEL", "info"),
    log_queries = false,
  },

  acl = { "0.0.0.0/0", "::/0" },

  upstreams = {
    {
      name = "yandex-ru",
      protocol = "udp",
      addr = "77.88.8.8:53",
      zones = { "ru." },
      timeout_ms = 1200,
    },
    {
      name = "global-primary",
      protocol = "udp",
      addr = "188.93.16.19:53",
      zones = { "." },
      timeout_ms = 1200,
    },
    {
      name = "global-backup",
      protocol = "udp",
      addr = "188.93.17.19:53",
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

  hosts = {
    file = "../hosts.txt",
    ttl = 120,
  },

  plugins = {
    enabled = true,
    timeout_ms = 20,
    entries = {
      { name = "lua-policy", runtime = "lua", path = "../scripts/policy.lua" }
    },
  },

  blacklist = {
  },

  control = {
    restart_backoff_ms = 200,
    restart_max_backoff_ms = 5000,
    max_consecutive_failure = 0,
    min_stable_run_ms = 10000,
  },
}
