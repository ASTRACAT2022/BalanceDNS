# BalanceDNS — Threat Intelligence

Threat Intelligence lets BalanceDNS block known malicious domains (C2, phishing,
malware, scam, cryptomining, …) sourced from external threat feeds and an
operator-owned list, without rewriting the DNS core. It is an **additive** layer:
DNS keeps serving throughout refreshes, and a feed outage never takes the
resolver down or answers from a half-built list.

## Why this architecture

The sandboxed Lua policy engine in BalanceDNS is intentionally restricted: it
opens only `base`, `table`, `string`, `math` (no `os`/`io`/`package`, no network,
no timers, no background tasks, no durable shared state). Policy scripts are
re-evaluated on every query. That design is correct for a security boundary, but
it means a policy cannot itself fetch feeds, keep state, or run scheduled
updates.

So Threat Intelligence is implemented with the minimal API extension the engine
already anticipates:

1. A **Go subsystem** (`internal/threat`) owns fetching, parsing, reputation
   scoring, the atomic snapshot, the disk cache, and the background updater.
2. A **single read-only Lua hook** (`threat.lookup(qname)`) exposes the verdict
   to policy scripts. Everything else stays sandboxed.
3. The policy script (`scripts/threat_intelligence.lua`) is a pure predicate:
   it asks `threat.lookup` and returns `BLOCK` or `FORWARD`.

The block response (NXDOMAIN vs REFUSED vs DROP) is chosen in Go config via
`plugins.block_rcode` — no new plugin action type, no core rewrite.

## Components

| Component | File | Role |
|---|---|---|
| Snapshot + matcher | `internal/threat/snapshot.go`, `domain.go` | Immutable domain map with O(labels) exact+suffix lookup |
| Parsers | `internal/threat/parser.go` | domains / hosts / rpz / json formats, validation, dedup |
| Reputation | `internal/threat/reputation.go` | Confidence × source-count thresholds |
| Feeds | `internal/threat/feed.go` | SSRF-hardened fetch with bounded body/timeout |
| Updater | `internal/threat/updater.go` | Background loop, atomic swap, disk cache, sanity guards |
| Metrics | `internal/threat/metrics.go` | Prometheus counters/gauges |
| Manager | `internal/threat/manager.go` | Top-level lookup + lifecycle |
| Lua hook | `internal/plugin/threat_hook.go` | Exposes `threat.lookup()` to sandbox |
| Policy | `scripts/threat_intelligence.lua` | Predicate: BLOCK/FORWARD |
| Config example | `configs/prod-threat-example.lua` | Wiring reference |

## Lookup path (hot query path)

```
policy threat_intelligence.lua
  -> threat.lookup(qname)                    (read-only, never blocks on network)
  -> th.Updater.Lookup(qname)
       1. allowlist  (any parent match)  -> allow, highest priority
       2. custom ASTRACAT blocklist      -> block, max priority after allowlist
       3. threat snapshot (exact+suffix) -> block iff reputation says so
  -> { block=true, reason, category } -> policy returns BLOCK
```

Every snapshot is immutable and swapped atomically behind one pointer; lookups
hold a short RLock and never wait on a fetch. A 2M-domain snapshot costs the
same per-query lookup as a 100-domain one.

## Zero-downtime guarantees

- **Refreshes are atomic.** The compiled snapshot is swapped whole. At no point
  is a query answered against a partially built list.
- **Fail-open default.** `fail_mode = "open"`: if the subsystem errors, the
  policy forwards (normal resolution). A broken feed or missing disk cache never
  turns legitimate traffic into blocks.
- **Disk cache.** `snapshot.json` in `disk_cache_dir` persists the last good
  snapshot; on restart DNS serves immediately from it while feeds warm.
- **Collapse guard.** If a successful fetch suddenly yields almost nothing
  (e.g. a feed that was 100k domains became 3), the update is rejected and the
  previous snapshot stays active.
- **No DNS-core rewrite.** The change is additive: a new subsystem + one Lua
  hook + a policy entry.

## Configuration

See `configs/prod-threat-example.lua` for a fully annotated example. Key
settings (top-level `threat` block):

| Field | Default | Meaning |
|---|---|---|
| `enabled` | false | Master switch (Threat subsystem + hook) |
| `default_action` | `NXDOMAIN` | What to return for a blocked query: `NXDOMAIN` \| `REFUSED` \| `DROP` |
| `fail_mode` | `open` | `open` \| `closed` |
| `update_interval` | 14400 | Feed refresh cadence, seconds |
| `request_timeout_ms` | 15000 | Per-feed fetch timeout |
| `max_feed_bytes` | 67108864 | Hard body cap per feed |
| `max_domains` | 0 | Optional cap on distinct domains (0 = unlimited) |
| `retry_count` / `backoff_seconds` | 3 / 30 | Failed-cycle backoff (keeps old snapshot) |
| `disk_cache_dir` | `/var/lib/balancedns/threat-intelligence` | Persisted last-good snapshot |
| `allowlist_file` | – | Domains/parents never blocked (highest priority) |
| `custom_blocklist_file` | – | ASTRACAT custom blocks (max priority after allowlist) |
| `minimum_sources` | 2 | Distinct feeds a low/medium IOC must appear in to block |
| `block_high_confidence` | true | Block single high-confidence hits |
| `block_medium_confidence` | false | Block medium confidence (only via minimum_sources) |

Block response for the *policy* path is set once via **`plugins.block_rcode`**
(`REFUSED` legacy default | `NXDOMAIN` | `DROP`). Keep `threat.default_action`
consistent with it.

### Feeds

```lua
feeds = {
  {
    name = "astracat-c2",
    url = "https://feeds.example/c2.txt",   -- HTTPS only (SSRF-hardened)
    format = "domains",                       -- domains | hosts | rpz | json
    confidence = "high",                      -- low | medium | high | custom
    category = "botnet_c2",                   -- malware | botnet_c2 | phishing |
                                              --  scam | cryptomining |
                                              --  malicious_redirector |
                                              --  custom_abuse | unknown
    enabled = true,
    min_entries = 10,                         -- reject feeds that collapse below this
  },
}
```

Supported formats:

- **domains** — one domain per line, `#` comments/blank lines ignored, `*.`/`.`
  prefixes become suffix rules.
- **hosts** — `/etc/hosts`-style (`IP hostname [hostname...]`); hostnames used,
  IPs ignored.
- **rpz** — `domain CNAME .` / `domain .` lines; `;`/`#`/`//` comments ignored.
- **json** — array of objects (`"domain"`/`"host"`/`"ioc":{...}`) or object with
  `"domains"`/`"hosts"`/`"blocklist"` string arrays.

URLs are validated before fetch: only `http`/`https`, no `localhost`, no
cloud-metadata endpoints, no loopback/private literal IPs, max 5 redirects.

## Enable procedure (zero-downtime)

1. Copy `scripts/threat_intelligence.lua` to the path referenced in
   `plugins.entries` and add the entry after any local rewrite policy.
2. Create (possibly empty) `allowlist_file` and `custom_blocklist_file`.
3. Set `plugins.block_rcode` and the `threat` block; set real feed URLs.
4. Restart balanceDNS once. The first background update writes `snapshot.json`;
   later restarts seed from it instantly.
5. Confirmed by metrics (below) — the resolver never restarts mid-answer.

## Rollback

Instant, low-risk:

1. Remove the `threat-intelligence` entry from `plugins.entries` (or set
   `plugins.block_rcode = "REFUSED"`/remove it to restore legacy block rcode).
2. Set `threat.enabled = false` (or delete the `threat` block).
3. Restart. Previous resolver behavior is fully restored; the Go subsystem
   simply never starts.

## Metrics

`balancedns_threat_*` are registered on the main metrics listener:

- `threat_updates_total{result=succeeded|failed}`
- `threat_update_duration_seconds`
- `threat_feed_fetches_total{feed,result}` / `threat_feed_failures_total{feed}`
- `threat_feed_iocs{feed}`
- `threat_lookups_total{result=miss|matched|allowlist}`
- `threat_blocked_total{reason=custom|high_confidence|min_sources}`
- `threat_observed_total{reason}`

All labels are bounded (per-feed and fixed outcome values), consistent with the
BalanceDNS metric-label policy.

## Failure-mode summary

| Condition | Result |
|---|---|
| Feed fetch/parse error | Keep old snapshot; log; count `feed_failures` |
| All feeds fail | Keep old snapshot; custom blocklist still enforced |
| Update collides (collapse guard) | Reject update; keep old snapshot |
| Disk cache missing at boot | Serve empty snapshot; first update fills it |
| Lua policy without `threat` hook | Fail open → FORWARD |
| `fail_mode = closed` (opt-in) | On subsystem error, block query (dangerous; off by default) |
| Block rcode DROP | Send no response (client retries) |
