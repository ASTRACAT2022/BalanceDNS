# BalanceDNS

BalanceDNS is a high-performance DNS proxy and caching balancer written in Rust, supporting UDP, TCP, DoT, and DoH.

## Key Features

- **Multi-protocol support**: UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS.
- **Advanced Balancing**: `fastest`, `round_robin`, and `consistent_hash` algorithms.
- **Lua Configuration**: Flexible and dynamic configuration using Lua.
- **Smart Caching**: Efficient caching with TTL management.
- **Security**: Built-in protection against ANY/DNSKEY queries, remote blocklists, and Lua sandboxing.
- **Monitoring**: Prometheus metrics and automated health checks.

## Quick Start

The easiest way to get started is by using the automatic installer:

```bash
sudo ./install.sh
```

## Configuration

BalanceDNS uses **Lua** for all configurations. The default configuration file is generated at `/etc/balancedns.lua`.

Example:

```lua
return {
    server = {
        udp_listen = "0.0.0.0:53",
        tcp_listen = "0.0.0.0:53",
    },
    balancing = {
        algorithm = "fastest",
    },
    upstreams = {
        {
            name = "cloudflare",
            proto = "udp",
            addr = "1.1.1.1:53",
        },
    },
}
```

## Documentation

- [Full Manual (Russian)](MANUAL_RU.md)
- [Lua Sandbox Details](LUA_SANDBOX_MANUAL.md)

## Development

Build the project:
```bash
cargo build --release
```

Run tests:
```bash
cargo test
```

## License

This project is licensed under the MIT License.
