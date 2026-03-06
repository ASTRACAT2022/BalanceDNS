# ASTRACAT DNS

ASTRACAT DNS is a recursive DNS resolver written in Go with DNSSEC validation, policy controls, plugins, and Prometheus metrics.

## Key Capabilities

- Built-in recursive resolver (no external forwarder required)
- Optional `miekg/unbound` backend via `resolver_type: "unbound"`
- DNSSEC validation (`AD` on validated answers)
- UDP/TCP DNS listener
- ODoH endpoint support
- Policy engine (block/rewrite/load-balancing)
- `dnsdist`-compatible policy layer (`dnsdist_compat_*`)
- Plugins: `hosts`, `adblock`, `dnsdist_compat`, `odoh`
- Prometheus metrics and admin panel

## Quick Start

```bash
go build -o dns-resolver .
./dns-resolver
```

By default, the resolver reads `config.yaml` from the working directory.

To build with Unbound backend support:

```bash
CGO_ENABLED=1 go build -tags unbound -o dns-resolver .
```

`libunbound` headers/runtime must be installed on the system.

## Configuration

Main config file: `config.yaml`

Important sections:

- Listener and ports: `listen_addr`, `dot_addr`, `odoh_addr`
- TLS/ACME: `cert_file`, `key_file`, `acme_*`
- Resolver backend: `resolver_type` (`recursor`/`knot`/`unbound`)
- Recursor and DNSSEC: `recursor_*`, `dnssec_*`
- Unbound tuning: `root_anchor_path`, `unbound_*`
- Security: `attack_protection_enabled`, `drop_any_queries`, rate limits
- Policy engine: `policy_*`
- Plugins: `hosts_*`, `adblock_*`, `dnsdist_compat_*`

## dnsdist Compatibility Layer

Enable:

```yaml
dnsdist_compat_enabled: true
```

The compatibility layer supports:

- banned client IP drop (`banned_ips.txt`)
- `ANY` query drop
- suffix drops
- suffix/exact spoofing via `sni_proxy_ips.txt`
- `hosts.txt` overrides (`A` spoof, `AAAA` NOERROR empty)
- garbage domains to `NXDOMAIN`

Default file paths are in `config.yaml` and point to `/etc/dnsdist/*.txt`.

## Metrics

Prometheus endpoint is exposed on `metrics_addr` (default `0.0.0.0:9090`) at `/metrics`.

Key metrics:
- `dns_resolver_qps` - global queries per second
- `dns_resolver_qps_by_transport{transport="udp|tcp|dot|doh|odoh"}` - QPS by transport
- `dns_resolver_total_queries` - total DNS queries
- `dns_resolver_requests_by_transport_total{transport="..."}` - total requests by transport
- `dns_resolver_requests_total{transport,outcome}` - requests by outcome
- `dns_resolver_request_duration_seconds{transport,rcode}` - request latency histogram
- `dns_resolver_response_codes_total{code}` - responses by DNS RCODE
- `dns_resolver_query_types_total{type}` - query volume by RR type
- `dns_resolver_requests_inflight` - current in-flight requests
- `dns_resolver_uptime_seconds` - resolver uptime

Useful PromQL examples:
- `sum(dns_resolver_qps_by_transport)`
- `dns_resolver_qps_by_transport`
- `sum(rate(dns_resolver_requests_total[1m])) by (transport, outcome)`
- `sum(rate(dns_resolver_response_codes_total[5m])) by (code)`
- `histogram_quantile(0.95, sum(rate(dns_resolver_request_duration_seconds_bucket[5m])) by (le, transport))`

## Admin Panel

Set `admin_addr`, `admin_username`, and `admin_password` in `config.yaml`.

## Deployment Docs

- Deployment guide: `DEPLOYMENT.md`
- User manual: `docs/user_manual.md`
- Admin manual: `docs/admin_manual.md`

## TLS Auto-Fix (No Manual Paths)

If DoH/DoT are disabled because `cert_file` and `key_file` do not match, run:

```bash
sudo astracat-fix-tls
```

What it does automatically:
- finds a valid matching cert/key pair (prefers Let's Encrypt `live/*`)
- copies it to `/opt/astracatdns/certs/`
- updates `config.yaml` (`cert_file`, `key_file`, `acme_enabled: false`)
- restarts `astracat-dns` and prints TLS startup logs
