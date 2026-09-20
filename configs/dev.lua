return {
  listen = {
    dns = "127.0.0.1:15353",
    metrics = "127.0.0.1:19090",
    read_timeout_ms = 2000,
    write_timeout_ms = 2000,
    reuse_port = false,
    reuse_addr = false,
    udp_size = 1232,
  },
  logging = { level = "info", log_queries = false },
  acl = { "0.0.0.0/0", "::/0" },
  upstreams = {
    {
      name = "test-upstream",
      protocol = "udp",
      addr = "8.8.8.8:53",
      zones = { "." },
      timeout_ms = 1200,
    },
  },
  routing = { chain = { "blacklist", "hosts", "cache", "lua_policy", "upstream" } },
  cache = {
    enabled = true,
    capacity = 10000,
    min_ttl_seconds = 5,
    max_ttl_seconds = 600,
  },
  hosts = { file = "", ttl = 60 },
  plugins = { enabled = false, timeout_ms = 20 },
  blacklist = {},
  control = {
    restart_backoff_ms = 200,
    restart_max_backoff_ms = 5000,
    max_consecutive_failure = 0,
    min_stable_run_ms = 10000,
  },
}
