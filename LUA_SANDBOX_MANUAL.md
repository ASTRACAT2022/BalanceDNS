# BalanceDNS Lua And Sandbox Manual

## Purpose

This manual explains:

1. How BalanceDNS isolates its internal components for production use.
2. How native plugins and Lua components are loaded.
3. What the built-in sandbox does and does not protect against.
4. How to safely deploy Lua logic on a high-load resolver.

## Isolation Model

BalanceDNS now uses multiple layers of isolation.

### 1. Service-Level Sandbox

The main process is sandboxed by systemd in [balancedns.service](/Users/astracat/BalanceDNS/balancedns.service):

- dedicated unprivileged user
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `PrivateTmp=true`
- `PrivateDevices=true`
- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`
- memory, task and file-descriptor limits

This is the OS-level sandbox for the whole resolver process.

### 2. Runtime Component Isolation

Inside the process, major components are separated logically:

- UDP ingress uses bounded worker queues
- TCP / DoT / DoH use fixed worker pools
- stale refresh runs with a hard thread cap
- remote hosts and blocklist refreshers run independently
- metrics listener is isolated from DNS listeners

If one queue is overloaded, the runtime now applies backpressure instead of growing forever.

### 3. Extension Sandbox

BalanceDNS supports two extension types:

- native plugins: dynamic libraries loaded into the process
- Lua components: scripts executed through an embedded Lua runtime

Both extension types have runtime guards:

- panic / error isolation
- consecutive-failure circuit breaker
- packet size limits
- logging of failures

Lua gets an additional language-level sandbox described below.

## Important Security Note

Lua components are sandboxed much more strongly than native plugins.

### Lua

Lua components are restricted by BalanceDNS itself:

- dangerous globals are removed: `os`, `io`, `package`, `debug`, `dofile`, `loadfile`, `require`, `collectgarbage`
- instruction budget is enforced for initialization and hook execution
- script output is capped to DNS packet size
- repeated failures disable the script automatically

### Native Plugins

Native plugins are only guarded, not truly sandboxed.

They run in the same process and address space as the resolver.

BalanceDNS protects against many failure modes:

- plugin panic isolation
- invalid return handling
- size limits
- automatic disable after repeated failures

But a malicious or memory-unsafe native plugin can still corrupt the process because it is native code.

For untrusted logic, prefer Lua.

## Lua Configuration

Add a `[lua]` section to the config:

```toml
[lua]
scripts = [
  "/var/lib/balancedns/lua/query_logger.lua"
]

[lua.settings]
mode = "observe"

[lua.sandbox]
max_packet_bytes = 4096
disable_after_failures = 8
init_instruction_limit = 500000
hook_instruction_limit = 100000

[[lua.components]]
path = "/var/lib/balancedns/lua/query_logger.lua"
enabled = true

[lua.components.settings]
mode = "log-only"
```

Lua components are loaded during startup. If a script fails to load, the resolver keeps starting, but the broken script is skipped.
`lua.settings` are shared defaults. `lua.components.settings` override them per script.

## Lua Hooks

Each script may define either or both functions:

```lua
function balancedns_pre_query(packet)
    return nil, false
end

function balancedns_post_response(packet)
    return nil, false
end
```

### Return Contract

Each hook returns two values:

```lua
return packet_or_nil, respond_boolean
```

Rules:

- `nil, false` means "do nothing"
- `raw_packet_string, false` means "replace packet and continue pipeline"
- `raw_packet_string, true` means "return this packet immediately"

The first value must be either `nil` or a Lua string containing raw DNS bytes.

## Lua Helper API

BalanceDNS injects a global table called `balancedns`.

Available helpers:

- `balancedns.qname(packet)` -> FQDN string or `nil`
- `balancedns.qtype(packet)` -> integer or `nil`
- `balancedns.tid(packet)` -> integer or `nil`
- `balancedns.rcode(packet)` -> integer or `nil`
- `balancedns.len(packet)` -> packet length
- `balancedns.hex(packet)` -> lowercase hex string
- `balancedns.from_hex(hex_string)` -> raw byte string or `nil`
- `balancedns.log(message)` -> write to resolver logs

Configuration values from TOML are available in:

- `balancedns.config`
- `balancedns.component.path`

## Example Script

Example file:

[examples/lua/query_logger.lua](/Users/astracat/BalanceDNS/examples/lua/query_logger.lua)

This script:

- logs incoming query metadata
- logs outgoing response metadata
- does not modify traffic

## Failure Handling

Every extension component has a circuit breaker.

Current behavior:

- after 8 consecutive failures, the component is disabled
- disabled components stop participating in the request pipeline
- the resolver continues serving traffic

This applies to:

- each native plugin independently
- each Lua script independently

## Production Deployment Guidance

### Recommended Policy

Use this split:

- critical packet path logic: built-in BalanceDNS features first
- light custom policy and observability: Lua
- only highly trusted, performance-sensitive code: native plugins

### Good Lua Use Cases

- query logging
- light policy routing
- tagging / tracing
- controlled packet rewrites
- safe experimentation before moving logic into Rust

Important:

- if you need to answer from a remote hosts file refreshed on a timer, use
  `[hosts_remote]` in the main config instead of Lua
- Lua scripts in the sandbox do not fetch HTTP sources or manage their own
  periodic refresh loop

### Bad Lua Use Cases

- very heavy per-packet parsing
- large string allocations on every request
- trying to reimplement the whole resolver in script

## High-Load Advice

For busy public resolvers:

- keep Lua scripts short and branch-light
- avoid converting every packet to hex unless necessary
- prefer `balancedns.qname()` / `balancedns.qtype()` over packet-wide transformations
- load as few scripts as possible on the hot path
- treat native plugins as privileged code
- keep metrics enabled and watch overload counters

Useful metrics:

- `balancedns_client_queries_dropped`
- `balancedns_client_connections_rejected`
- `balancedns_client_queries_errors`
- `balancedns_upstream_timeout`
- `balancedns_inflight_queries`

## Example Production Layout

```text
/etc/balancedns.toml
/var/lib/balancedns/lua/query_logger.lua
/var/lib/balancedns/tls/server.crt
/var/lib/balancedns/tls/server.key
```

Example config fragment:

```toml
[plugins]
libraries = []

[lua]
scripts = [
  "/var/lib/balancedns/lua/query_logger.lua"
]
```

## Hardening Summary

What is sandboxed now:

- service process via systemd
- queues and workers via bounded runtime limits
- stale refresh via hard cap
- Lua via restricted globals and instruction limit
- extension failures via per-component circuit breaker

What is not fully sandboxed:

- native plugins are still in-process native code

If you need hard multi-tenant isolation for custom logic, the next step is an external policy sidecar over RPC or a separate worker process model.
