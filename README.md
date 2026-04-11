# BalanceDNS (MVP+)

BalanceDNS is a lightweight DNS resolver/forwarder in Go with policy-based routing, sandboxed plugins (Lua and Go-exec), high-speed sharded LRU cache, and Prometheus metrics.

## Features

- UDP + TCP DNS listeners (`miekg/dns`)
- Processing chain: `Blacklist -> Cache -> Lua/Plugin Policy -> Upstream`
- Multi-upstream routing by zone with automatic fallback between matching upstreams
- Upstream protocols:
  - `udp`
  - `tcp`
  - `dot` (DNS-over-TLS)
  - `doh` (DNS-over-HTTPS)
- Thread-safe sharded LRU cache (64 shards on large capacity) with min/max TTL bounds
- Sandbox plugin engine:
  - Lua runtime in clean state without `os`, `io`, package loading
  - Go plugins executed as isolated subprocesses with strict timeout and empty environment
- Listener/network stack tuning (`reuse_port`, `reuse_addr`, UDP size, read/write timeouts)
- Built-in supervisor/control plane:
  - per-component restart with backoff
  - crash loop protection (`max_consecutive_failure`)
  - health/readiness/status endpoints
- Prometheus metrics
- Graceful shutdown (`SIGINT`, `SIGTERM`)

## Metrics

- `balancedns_queries_total`
- `balancedns_cache_hits_total`
- `balancedns_upstream_latency_seconds`
- `balancedns_plugin_execution_errors`
- `balancedns_component_up`
- `balancedns_component_restarts_total`

## Run

```bash
go run ./cmd/balancedns -config configs/balancedns.yaml
go run ./cmd/balancedns -config configs/balancedns.lua
```

Detailed Russian manual:
- `docs/MANUAL_RU.md`
- `docs/POLICIES_RU.md` (практика по политикам ответов)

## Config

See `configs/balancedns.yaml` and `configs/balancedns.lua`.

YAML, JSON and Lua are supported.

Lua config must return table:

```lua
return {
  listen = { dns = env("BALANCEDNS_DNS_ADDR", ":5353") },
  upstreams = {
    { name = "global-doh", protocol = "doh", doh_url = "https://dns.google/dns-query", zones = {"."} }
  }
}
```

### Upstream examples

```yaml
upstreams:
  - name: "global-doh"
    protocol: "doh"
    doh_url: "https://dns.google/dns-query"
    zones: ["."]
    timeout_ms: 1500

  - name: "global-dot"
    protocol: "dot"
    addr: "1.1.1.1:853"
    tls_server_name: "cloudflare-dns.com"
    zones: ["."]
    timeout_ms: 1500
```

### Control plane

```yaml
control:
  restart_backoff_ms: 200
  restart_max_backoff_ms: 5000
  max_consecutive_failure: 0
  min_stable_run_ms: 10000
```

- `0` in `max_consecutive_failure` means unlimited restart attempts.
- Health endpoints are served on metrics listener:
  - `/healthz`
  - `/readyz`
  - `/statusz`

## Plugin contract

### Lua plugin

```lua
function handle(question)
  -- question.domain, question.type, question.qtype
  return {
    action = "FORWARD" | "BLOCK" | "REWRITE" | "LOCAL_DATA",
    rewrite_domain = "example.org.",
    rewrite_type = "A",
    local_data = {
      ttl = 60,
      ip = "127.0.0.1",
      ips = {"127.0.0.1", "::1"}
    }
  }
end
```

### Go-exec plugin

Plugin process receives JSON on `stdin` and returns JSON to `stdout`:

Input:

```json
{"question":{"domain":"example.org.","type":"A","qtype":1}}
```

Output:

```json
{"action":"FORWARD"}
```

or

```json
{"action":"LOCAL_DATA","local_data":{"ips":["127.0.0.2"],"ttl":60}}
```

### Plugin entries

```yaml
plugins:
  enabled: true
  timeout_ms: 20
  entries:
    - name: "lua-policy"
      runtime: "lua"
      path: "scripts/policy.lua"
    - name: "go-policy"
      runtime: "go_exec"
      path: "/opt/balancedns/plugins/go-policy"
      timeout_ms: 10
```

Example Go plugin source: `scripts/go_policy_example.go` (build it into executable and use `runtime: "go_exec"`).

## Tests and checks

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/balancedns
```

## Systemd install

Linux/systemd installer:

```bash
./scripts/install-systemd.sh
```

The script builds binary, installs config and creates `balancedns.service` with hardening options.

## Docker

```bash
docker compose up -d --build
```

Files:
- `Dockerfile`
- `docker-compose.yml`
- `configs/docker.yaml`
