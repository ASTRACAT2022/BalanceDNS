local bind_ip = env("BALANCEDNS_BIND_IP", "144.31.151.64")
local metrics_ip = env("BALANCEDNS_METRICS_IP", "0.0.0.0")

local function addr(ip, port)
  return string.format("%s:%d", ip, port)
end

return {
  listen = {
    dns = addr(bind_ip, 53),
    dot = addr(bind_ip, 853),
    doh = addr(bind_ip, 443),
    doh_path = "/dns-query",
    tls_cert_file = env("BALANCEDNS_TLS_CERT", "/etc/balancedns/certs/fullchain.cer"),
    tls_key_file = env("BALANCEDNS_TLS_KEY", "/etc/balancedns/certs/key.key"),
    metrics = addr(metrics_ip, 9091),
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
      addr = "95.85.95.85:53",
      zones = { "." },
      timeout_ms = 1200,
    },
    {
      name = "global-backup",
      protocol = "udp",
      addr = "2.56.220.2:53",
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
    enabled = false,
    timeout_ms = 20,
  },

  blacklist = {},

  control = {
    restart_backoff_ms = 200,
    restart_max_backoff_ms = 5000,
    max_consecutive_failure = 0,
    min_stable_run_ms = 10000,
  },
}
