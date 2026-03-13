# ASTRACAT DNSlang Manual

`DNSlang` is the native Astracat policy language for local DNS decisions.

It is designed for production use when you want one readable policy file instead of:

- scattered `policy_*` YAML rules
- dnsdist-compat text files
- ad-hoc plugin logic for local answers

`DNSlang` runs inside the resolver itself. No external `dnsdist` process is required.

## 1. Where DNSlang fits in the request path

For standard DNS (`udp`/`tcp`) the simplified order is:

1. hard request validation and attack limits
2. `DNSlang` `preflight`
3. preflight plugins
4. built-in `drop_any_queries`
5. built-in `policy_*`
6. `DNSlang` `policy`
7. cache
8. regular plugins
9. recursive resolver

For `DoT` and `DoH/ODoH`:

1. request validation
2. `DNSlang` `preflight`
3. preflight plugins
4. built-in `drop_any_queries`
5. `DNSlang` `policy`
6. regular plugins
7. upstream resolution

Important:

- first matching rule wins inside each `phase`
- if you want `ANY` to be controlled by `DNSlang`, set `drop_any_queries: false`
- if `drop_any_queries: true`, the built-in global protection still wins after `preflight`

## 2. Enable it in config.yaml

```yaml
dnslang_enabled: true
dnslang_policy_path: "/etc/astracat/dnslang/policy.dns"
```

Recommended production layout:

- config: `/opt/astracatdns/config.yaml`
- policy file: `/etc/astracat/dnslang/policy.dns`
- optional sets: `/etc/astracat/dnslang/*.txt`

Create the directory:

```bash
mkdir -p /etc/astracat/dnslang
```

## 3. Language structure

The file contains two top-level constructs:

- `set`
- `rule`

Example:

```dnslang
set banned_ips = ipset("/etc/astracat/dnslang/banned_ips.txt")
set tracker_suffixes = suffixes(["doubleclick.net", "googlesyndication.com"])

rule drop_banned_clients {
  phase = preflight
  when = client_ip in banned_ips
  action = drop
}

rule refuse_trackers {
  phase = policy
  when = qname suffix in tracker_suffixes
  action = refuse
}
```

## 4. Supported phases

### `phase = preflight`

Use for:

- client IP drops
- `ANY` suppression
- early abusive suffix filtering
- transport-specific drops before cache/plugins

### `phase = policy`

Use for:

- `REFUSED`
- `NXDOMAIN`
- empty `NOERROR`
- local `A`/`AAAA`/`CNAME`/`TXT` answers
- IP-pool based local balancing

## 5. Supported fields

You can use these fields in `when`:

- `qname`
- `qtype`
- `qclass`
- `transport`
- `client_ip`

Examples:

```dnslang
when = qtype == ANY
when = transport == doh
when = qtype in [A, AAAA]
when = client_ip in banned_ips
when = qname == "api.example.com"
when = qname suffix "example.com"
when = qname suffix in tracker_suffixes
```

## 6. Supported operators

- `==`
- `!=`
- `in`
- `suffix`
- `suffix in`
- `and`
- `or`
- `not (...)`

Examples:

```dnslang
when = qtype == A and transport in [udp, tcp]
when = not (qname suffix "safe.example")
when = client_ip in corp_nets and qname suffix "internal.example"
```

## 7. Supported set types

### `strings(...)`

Case-insensitive generic string list.

```dnslang
set transports = strings(["udp", "tcp"])
```

### `domains(...)`

Exact DNS names.

```dnslang
set exact_domains = domains(["api.example.com", "cdn.example.com"])
```

### `suffixes(...)`

Suffix matches for domain names.

```dnslang
set suffixes_block = suffixes(["doubleclick.net", "hotjar.com"])
```

### `ipset(...)`

Single IPs and CIDR ranges.

```dnslang
set banned_ips = ipset("/etc/astracat/dnslang/banned_ips.txt")
```

File format:

```text
192.0.2.10
198.51.100.0/24
2001:db8::/32
```

### `ippool(...)`

Pool of IPs for spoof/load-balance answers.

```dnslang
set edge_pool = ippool("/etc/astracat/dnslang/edge_pool.txt")
```

File format:

```text
198.51.100.10
198.51.100.11
2001:db8::20
```

### `hosts(...)`

Exact local host mapping.

```dnslang
set internal_hosts = hosts("/etc/astracat/dnslang/hosts.txt")
```

File format:

```text
203.0.113.10 app.internal
203.0.113.11 api.internal
2001:db8::10 app.internal
```

## 8. Supported actions

### `drop`

Silent local drop. Best for preflight abuse handling.

```dnslang
action = drop
```

### `refuse`

Return `REFUSED`.

```dnslang
action = refuse
```

### `nxdomain`

Return `NXDOMAIN`.

```dnslang
action = nxdomain
```

### `empty`

Return `NOERROR` with empty answer section.

```dnslang
action = empty
```

### `answer <TYPE> <VALUE> ttl <N>`

Synthetic static answer.

```dnslang
action = answer A "10.10.10.5" ttl 120
action = answer AAAA "2001:db8::53" ttl 120
action = answer CNAME "edge.example.net." ttl 60
action = answer TXT "blocked-by-policy" ttl 30
```

### `answer from <hosts_set> ttl <N>`

Lookup exact name in a `hosts(...)` set.

```dnslang
action = answer from internal_hosts ttl 120
```

### `spoof from <pool_set> ttl <N>`

Use the first matching IP from an `ippool(...)`.

```dnslang
action = spoof from edge_pool ttl 30
```

### `load_balance from <pool_set> ttl <N> strategy <S>`

Strategies currently supported:

- `round_robin`
- `random`
- `first`

Example:

```dnslang
action = load_balance from edge_pool ttl 20 strategy round_robin
```

## 9. Real production examples

### 9.1 Block all `ANY`

```dnslang
rule block_any {
  phase = preflight
  when = qtype == ANY
  action = drop
}
```

Recommended config:

```yaml
drop_any_queries: false
dnslang_enabled: true
```

This gives control to the policy file instead of the hardcoded global switch.

### 9.2 Ban abusive clients

```dnslang
set banned_ips = ipset("/etc/astracat/dnslang/banned_ips.txt")

rule drop_banned_clients {
  phase = preflight
  when = client_ip in banned_ips
  action = drop
}
```

### 9.3 Refuse tracker families

```dnslang
set tracker_suffixes = suffixes([
  "googlesyndication.com",
  "doubleclick.net",
  "adcolony.com",
  "hotjar.com"
])

rule refuse_trackers {
  phase = policy
  when = qname suffix in tracker_suffixes
  action = refuse
}
```

### 9.4 Internal A/AAAA answers from hosts file

```dnslang
set internal_hosts = hosts("/etc/astracat/dnslang/hosts.txt")

rule internal_hosts_answers {
  phase = policy
  when = qname in internal_hosts and qtype in [A, AAAA]
  action = answer from internal_hosts ttl 120
}
```

### 9.5 Return empty `AAAA`

```dnslang
rule empty_ipv6_for_specific_zone {
  phase = policy
  when = qtype == AAAA and qname suffix "legacy.example"
  action = empty
}
```

### 9.6 Different policy by transport

```dnslang
rule drop_any_on_doh {
  phase = preflight
  when = qtype == ANY and transport == doh
  action = drop
}

rule refuse_any_on_dot {
  phase = preflight
  when = qtype == ANY and transport == dot
  action = refuse
}
```

### 9.7 Local edge pool with round-robin

```dnslang
set edge_pool = ippool("/etc/astracat/dnslang/edge_pool.txt")

rule edge_answers {
  phase = policy
  when = qname suffix "edge.example" and qtype == A
  action = load_balance from edge_pool ttl 15 strategy round_robin
}
```

## 10. Migration from dnsdist_compat

### Old style

```yaml
dnsdist_compat_enabled: true
dnsdist_compat_banned_ips_path: "/etc/dnsdist/banned_ips.txt"
dnsdist_compat_hosts_path: "/etc/dnsdist/hosts.txt"
dnsdist_compat_drop_suffixes:
  - "dhitc.com"
```

### Native DNSlang style

```dnslang
set banned_ips = ipset("/etc/dnsdist/banned_ips.txt")
set compat_hosts = hosts("/etc/dnsdist/hosts.txt")
set early_drop = suffixes(["dhitc.com"])

rule compat_banned_ips {
  phase = preflight
  when = client_ip in banned_ips
  action = drop
}

rule compat_early_drop {
  phase = preflight
  when = qname suffix in early_drop
  action = drop
}

rule compat_hosts {
  phase = policy
  when = qname in compat_hosts and qtype in [A, AAAA]
  action = answer from compat_hosts ttl 60
}
```

## 11. Server deployment guide

Example paths from a typical Astracat production node:

- git repo: `/root/AstracatDNS`
- runtime dir: `/opt/astracatdns`
- service: `astracat-dns`

### Step 1. Create the policy file

```bash
mkdir -p /etc/astracat/dnslang
cp /opt/astracatdns/docs/examples/dnslang.policy.dns /etc/astracat/dnslang/policy.dns
```

### Step 2. Enable it in `/opt/astracatdns/config.yaml`

```yaml
dnslang_enabled: true
dnslang_policy_path: "/etc/astracat/dnslang/policy.dns"
drop_any_queries: false
```

### Step 3. Safe deploy

```bash
cd /root/AstracatDNS && \
GOCACHE=$(pwd)/.gocache go build -o /tmp/dns-resolver-new . && \
ts=$(date +%F_%H%M%S) && \
cp -a /opt/astracatdns "/root/astracat-backup-$ts" && \
systemctl stop astracat-dns && \
rsync -a --delete \
  --exclude '.git' \
  --exclude '.gocache' \
  --exclude 'config.yaml' \
  --exclude 'cache/' \
  --exclude 'cert.pem' \
  --exclude 'key.pem' \
  ./ /opt/astracatdns/ && \
install -m 755 /tmp/dns-resolver-new /opt/astracatdns/dns-resolver && \
systemctl start astracat-dns && \
systemctl status --no-pager astracat-dns
```

### Step 4. Validate after restart

Check logs:

```bash
journalctl -u astracat-dns -n 100 --no-pager
```

Check metrics:

```bash
curl -s http://127.0.0.1:7070/metrics | grep -E 'dns_resolver_policy_actions_total|dns_resolver_response_codes_total|dns_resolver_security_drops_total'
```

Check `ANY` blocking:

```bash
dig @127.0.0.1 example.com ANY +tcp
```

Expected result:

- timeout if you use `drop`
- `REFUSED` if you use `refuse`

## 12. Operational notes

- `DNSlang` is loaded on startup, not hot-reloaded
- missing files or syntax errors will abort startup when `dnslang_enabled: true`
- `answer from hosts_set` is only for exact names
- `load_balance from pool` currently supports `A` and `AAAA`
- `answer` currently supports `A`, `AAAA`, `CNAME`, `TXT`

## 13. Example starter file

Use [docs/examples/dnslang.policy.dns](/Users/astracat/Downloads/AstracatDNS-main/docs/examples/dnslang.policy.dns) as a base policy for production rollout.

