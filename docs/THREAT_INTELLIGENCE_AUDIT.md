# BalanceDNS — Threat Intelligence: Technical Audit & API Extension

Short version for reviewers: the requested Threat Intelligence feed/blocking
cannot be implemented inside the Lua policy sandbox as-is, so it is delivered
as a **Go subsystem + one minimal read-only Lua API extension** (`threat.lookup`),
per the design note in the spec that allows a minimal Lua API extension when the
engine lacks the needed capabilities.

## 1. Why the policy sandbox alone cannot do it

BalanceDNS's sandboxed Lua state is deliberately minimal (`internal/plugin/
engine.go`, `newSandboxState`):

```go
L := lua.NewState(lua.Options{SkipOpenLibs: true})
lua.OpenBase(L)
lua.OpenTable(L)
lua.OpenString(L)
lua.OpenMath(L)
```

There is **no** `os`, `io`, `package`, `coroutine`, network, timers, or durable
shared state. Policy scripts are re-`DoString`-ed and run fresh on **every
query**, with a per-query timeout (`plugins.timeout_ms`, default 20ms).

Therefore a single Lua script **cannot**:
- fetch threat feeds over HTTP(S) (no `os`/network);
- run background/scheduled updates (no timers, no persistent process);
- keep a large in-memory blocklist across queries (fresh state each query);
- load files or read config at runtime (no `io`/`package`);
- do 2M-entry suffix matching within a 20ms budget from Lua tables.

## 2. The minimal extension (design chosen)

Per the spec's own fallback ("Если существующему Lua engine не хватает
timers/background workers, реализовать наиболее подходящий механизм без
переписывания DNS core: внешний updater → готовый compiled/local snapshot →
Lua reload"), the implementation is:

| Concern | Where it lives | Why not in Lua |
|---|---|---|
| Feed fetching, SSRF guard, timeout | `internal/threat/feed.go` | Go has real net/http + hardened transport |
| Parsers (domains/hosts/rpz/json) | `internal/threat/parser.go` | Go, fast, safe |
| Reputation thresholds | `internal/threat/reputation.go` | Enforced once, not per query |
| Atomic compiled snapshot | `internal/threat/snapshot.go` | O(labels) map, 0 alloc |
| Background updater + disk cache | `internal/threat/updater.go` | Real goroutine + atomic swap |
| Metrics | `internal/threat/metrics.go` | Prometheus |
| **Lua API** | `internal/plugin/threat_hook.go` | `threat.lookup(qname)` → table/nil |

The Lua surface added to the sandbox is exactly **one read-only function**:
`threat.lookup(qname)`. It returns `nil` for "no threat" or a small immutable
table `{ matched, block, reason, category, base, sources }`. It never blocks on
the network (it reads the active snapshot under a short RLock). This is
backward-compatible: without a registered hook the `threat` global is absent and
the shipped policy fails open to `FORWARD`.

### Second extension: configurable block rcode

The block action previously always mapped to `REFUSED` (`server.go`). The spec
requires NXDOMAIN / REFUSED / DROP. A **single** backward-compatible field,
`plugins.block_rcode` (default `REFUSED`), was added. The `lua_policy` BLOCK
stage now honors it; DROP means "send no response" (nil response short-circuits
the DNS/DoH transports).

## 3. Exact changes

**New packages/files**
- `internal/threat/` — the whole subsystem (domain, snapshot, config, parser,
  reputation, feed, updater, manager, metrics, tests, benchmark).
- `internal/plugin/threat_hook.go` — Lua `threat.lookup` hook + tests.
- `scripts/threat_intelligence.lua` — the policy predicate.
- `configs/prod-threat-example.lua` — wiring reference.
- `docs/THREAT_INTELLIGENCE.md` — operator guide.

**Modified files**
- `internal/plugin/engine.go` — `LuaHook` option threaded through
  `NewEngineWithOptions` → `newSandboxState(hook)`; backward compatible.
- `internal/config/config.go` — `Config.Threat`, `ThreatConfig`,
  `ThreatFeedConfig`, `PluginConfig.BlockRcode`, defaults + validation.
- `internal/config/lua_loader.go` — (unchanged behavior; new fields flow via the
  existing Lua→JSON→struct pipeline).
- `internal/metrics/metrics.go` — `Registry()` accessor.
- `internal/app/server.go` — build + start threat manager, pass Lua hook,
  honor `block_rcode` (NXDOMAIN/REFUSED/DROP).
- `internal/app/threat_config.go` — `config.ThreatConfig` → `threat.Config`.

## 4. Zero-downtime properties (verified by tests)

- **Atomic swap:** snapshot replaced whole behind one pointer; readers see old
  or new, never partial. `TestUpdaterSwapOnSuccessAndKeepsOldOnFailure`.
- **Fail-open:** absent hook / subsystem error ⇒ FORWARD.
  `TestThreatLuaHookFailOpenWhenNilHook`.
- **All-feed failure keeps old snapshot:** verified test.
- **Disk cache seeds restart:** `TestUpdaterDiskCacheSeeds`.
- **Race-free:** `go test -race ./internal/threat/ ./internal/plugin/` clean.
- **HOT PATH:** `BenchmarkMatchIOC` — 2M domains, 0 alloc/op, ~3µs/lookup
  (suffix match is O(labels), bounded by domain depth).

## 5. Not covered (documented as out of scope)

- Per-`category` enforcement toggle is feed-level today (only blocking feeds
  contribute); a per-domain category whitelist is a future extension.
- `DROP` is implemented (nil response), but is not cache-friendly and should be
  used deliberately.
- `fail_mode="closed"` is configurable but off by default (dangerous).
