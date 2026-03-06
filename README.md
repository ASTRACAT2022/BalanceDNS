# ASTRACAT DNS

ASTRACAT DNS is a recursive DNS resolver written in Go with DNSSEC validation, policy controls, plugins, and Prometheus metrics.

## Key Capabilities

- Built-in recursive resolver (no external forwarder required)
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

## Configuration

Main config file: `config.yaml`

Important sections:

- Listener and ports: `listen_addr`, `dot_addr`, `odoh_addr`
- TLS/ACME: `cert_file`, `key_file`, `acme_*`
- Recursor and DNSSEC: `recursor_*`, `dnssec_*`
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

## Admin Panel

Set `admin_addr`, `admin_username`, and `admin_password` in `config.yaml`.

## Deployment Docs

- Deployment guide: `DEPLOYMENT.md`
- User manual: `docs/user_manual.md`
- Admin manual: `docs/admin_manual.md`
