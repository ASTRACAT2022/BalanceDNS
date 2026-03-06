# AstracatDNS User Manual

## 1. What It Is

AstracatDNS is a recursive DNS resolver in Go. It resolves domains directly, validates DNSSEC, and applies configurable policies before recursion.

## 2. Main Features

- Recursive DNS resolver (UDP/TCP)
- DNSSEC validation mode
- Hybrid caching and request deduplication
- Policy engine: block, rewrite, load-balance
- `dnsdist`-compatible policy rules
- `hosts` and `adblock` plugins
- ODoH support
- Prometheus metrics and web admin panel

## 3. Build and Run

```bash
go build -o dns-resolver .
./dns-resolver
```

By default it loads `config.yaml` from the current directory.

## 4. Basic Configuration

Edit `config.yaml`:

- DNS listener: `listen_addr`
- Metrics: `metrics_addr`, `prometheus_enabled`
- Admin panel: `admin_addr`, `admin_username`, `admin_password`
- Recursor: `recursor_cache_entries`, `recursor_cache_min_ttl`, `recursor_cache_max_ttl`
- DNSSEC: `dnssec_validate`, `dnssec_fail_closed`, `dnssec_trust_anchors`

## 5. dnsdist-Compatible Policies

Enable:

```yaml
dnsdist_compat_enabled: true
```

Policy files (default under `/etc/dnsdist/`):

- `banned_ips.txt` - client CIDRs/IPs to drop
- `sni_proxy_ips.txt` - spoof IP pool
- `domains_with_subdomains.txt` - suffix spoof list
- `custom.txt` - suffix spoof list
- `domains.txt` - exact spoof list
- `hosts.txt` - host overrides
- `garbage.txt` - exact NXDOMAIN list

Additional inline lists:

- `dnsdist_compat_drop_suffixes`
- `dnsdist_compat_late_drop_suffixes`

## 6. DNSSEC Behavior

When validation succeeds, responses are marked with `AD`.  
If `dnssec_fail_closed: true`, bogus validation returns `SERVFAIL`.

## 7. Secure DNS Endpoints

- DoT: set `dot_addr` and valid TLS cert/key
- ODoH: set `odoh_addr` and TLS cert/key

## 8. Monitoring

Prometheus endpoint:

```text
http://<host>:9090/metrics
```

## 9. Notes

- Cluster mode and cluster sync are not part of this version.
