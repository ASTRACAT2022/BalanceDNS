# BalanceDNS

**BalanceDNS** is a high-performance, fully asynchronous, and modular DNS platform written in **Rust**. It is designed to handle millions of concurrent tasks using the **tokio** runtime, solving common issues like I/O blocking, cache duplication, and plugin isolation.

## Architecture Overview

The platform is divided into several independent but closely related modules:

### 1. Server Module
Handles incoming traffic via UDP, TCP, and HTTP protocols. All incoming data is converted into a unified abstract format — **"frames"**. This abstraction simplifies flow management, ensuring fairness in resource distribution and protection against overloads (pacing).

### 2. Worker Module
Each received frame is transformed into an asynchronous task for the worker pool. The worker is the main request coordinator, first attempting to find a ready answer in the cache before delegating to recursive resolution.

### 3. Cache Module
Redesigned from scratch:
- **ARC (Adaptive Replacement Cache)**: Replaces classic key-value storage, providing more efficient data eviction and resistance to zone scanning attacks.
- **Consistent Hashing**: Instead of per-datacenter multicast, servers use consistent hashing to redirect requests to peers if the local cache is empty, optimizing memory usage.

### 4. Recursor Module
The logical "brain" of the system. It iteratively breaks down client DNS requests to query authoritative root servers. The recursor itself **does not perform network requests**; it builds the search chain and delegates network work to the Conductor.

### 5. Conductor Module
Manages all outgoing traffic to upstream servers:
- **Deduplication**: If multiple identical requests arrive simultaneously, the Conductor releases only one and queues others, significantly reducing network spam.
- **Smart Routing**: Continuously collects metrics (RTT, latency, packet loss) to choose the fastest authoritative server and optimal protocol.

### 6. Sandbox Module
Extends functionality through **WebAssembly (Wasm)** plugins:
- **Isolation**: Wasm modules run in protected memory; plugin failures do not crash the resolver.
- **Zero-copy Shared Memory**: Direct memory access between the host and Wasm sandbox avoids expensive data copying.
- **Hostcalls**: Heavy operations (like cryptography) are delegated to the Rust core, accelerating performance up to 4x.

## Key Features

- **Asynchronous & Scalable**: Powered by `tokio`.
- **High Performance**: Optimized caching and deduplication.
- **Secure Sandbox**: Wasm-based plugin system.
- **Modern Protocols**: Support for UDP, TCP, DoT, DoH, and oDoH.
