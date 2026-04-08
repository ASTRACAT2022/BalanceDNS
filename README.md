# BalanceDNS

This is an overview of the **BalanceDNS** DNS resolver architecture written in **Rust**. It replaces earlier designs that could no longer keep up with growing load because of blocking I/O, cache duplication, and weak plugin isolation.

Its foundation is the asynchronous **tokio** runtime. That lets the system process millions of concurrent tasks on a shared thread pool with *work stealing*, without allowing expensive requests to stall the whole queue.

## Architecture Overview

The platform is divided into several independent but tightly connected modules:

### 1. Server Module
Handles incoming traffic over UDP, TCP, and HTTP. Internally, all incoming data is normalized into a single abstract format: **"frames"**. That abstraction makes flow control easier, improves fairness across clients, and helps protect BalanceDNS from overload through pacing.

### 2. Worker Module
Every received frame becomes an asynchronous job for the worker pool. A worker is the main request coordinator: it applies policies first, checks the cache for a ready answer, and if there is no hit, hands the request off to the forwarding path.

### 3. Cache Module
BalanceDNS redesigned caching from the ground up:
- **ARC (Adaptive Replacement Cache)** replaces a classic key-value cache, giving better eviction behavior for unpopular data and better resistance to zone-scanning patterns.
- **Consistent hashing** replaces multicast-style cache fanout. Each server knows its nearby peers and forwards a miss to the right node instead of pushing fresh records to every server in the datacenter.

### 4. Conductor Module
Manages all outbound traffic to upstream servers:
- **Deduplication**: if a thousand identical requests arrive at once, such as after a hot cache entry expires, the Conductor sends only one upstream request and queues the rest behind it. That sharply reduces network spam.
- **Smart routing**: the module continuously collects metrics such as RTT, latency, and packet loss, then decides which authoritative server should answer fastest, which transport to use, and whether the request should be routed through a protected internal path.

### 5. Sandbox Module
To extend BalanceDNS with logging, DDoS protections, and modern protocols such as oDoH, the platform uses **WebAssembly (Wasm)** plugins:
- **Isolation**: Wasm modules run in protected memory, so a plugin crash does not bring down the resolver.
- **Zero-copy shared memory**: a shared memory region avoids repeated data copies between the host and the Wasm sandbox.
- **Hostcalls**: plugins can delegate expensive work back to the host. For example, cryptographic math inside Wasm can be slow, so heavy crypto operations are handed to the Rust core through hostcalls, improving performance by up to 4x.

## Forward Mode

The request path is:

1. Accept the client request over UDP, TCP, DoT, or DoH.
2. Normalize it into a `Frame`.
3. Run policy checks in `Worker`.
4. Serve from cache when possible.
5. On a miss, send the request through `Conductor` to the selected upstream.
6. Run post-response plugins and write the result back into cache.

Current policy layers include local hosts overrides, remote hosts, blocklists, request-type denies, routing rules, and Lua/native/Wasm plugins.

## Summary

**BalanceDNS** is a resilient, fully asynchronous, and modular platform. It addresses cache bloat, removes blocking I/O bottlenecks, and gives developers a safe way to ship new features through WebAssembly.
