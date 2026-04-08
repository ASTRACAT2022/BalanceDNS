# Wasm Remote Hosts Plugin

This component is intentionally tiny.

- `hosts_remote` refresh stays in the BalanceDNS core
- the Wasm module does not perform HTTP requests
- on `pre_query`, the module asks the host to resolve the packet against the
  host-side local/remote override maps

Build:

```bash
cargo build --release --target wasm32-unknown-unknown
```

Artifact:

```text
target/wasm32-unknown-unknown/release/balancedns_remote_hosts_wasm.wasm
```
