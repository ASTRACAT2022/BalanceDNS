# AstracatDNS User Manual

## Introduction
AstracatDNS is a high-performance, modular DNS resolver written in Go. It focuses on speed, privacy, and extensibility through a plugin system.

## Features
- **High Performance**: Optimized concurrency, lazy-loading disk cache, and efficient memory usage.
- **Privacy First**: Support for DNS-over-UDP/TCP with optional encryption (future).
- **AdBlock**: Integrated AdBlock plugin with parallel blocklist updates.
- **Customizable**: Hosts file support for local overrides.
- **Admin Panel**: Web-based interface for monitoring and management.

## Installation

### Prerequisites
- Go 1.24+ (if building from source)
- Linux or macOS

### Building from Source
```bash
go build -o AstracatDNS
```

## Configuration
The main configuration file is `config.yaml`.

```yaml
server:
  port: 53
  upstream: ["1.1.1.1:53", "8.8.8.8:53"]

admin:
  port: 8080
  username: astracat
  password: astracat  # Please change this immediately!

plugins:
  adblock:
     enabled: true
  adblock:
     enabled: true
     blocklists:
       - https://example.com/ads.txt

  # Secure DNS (DoT/DoH)
  # Requires valid TLS certificates
  do_t_addr: "0.0.0.0:853"
  do_h_addr: "0.0.0.0:443"
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
```

## Secure DNS (DoT/DoH/ODoH)
To enable DNS-over-TLS (DoT) or DNS-over-HTTPS (DoH), you must provide a valid TLS certificate and key in `config.yaml`.
- **DoT**: Listens on port 853 by default.
- **DoH**: Listens on port 443 by default at `/dns-query`.
- **ODoH**: Supported on the same DoH port. The server automatically generates a keypair on startup. Clients can fetch the config at `/odohconfigs`.

## Running the Server
```bash
sudo ./AstracatDNS
```
*Note: Binding to port 53 usually requires root privileges.*

## Client Setup
Configure your device or router to use the IP address of the server running AstracatDNS as its DNS server.

### macOS
1. Open System Settings -> Network.
2. Select your active network connection.
3. Click "Details..." -> "DNS".
4. Add the IP address of your AstracatDNS server.

### Linux (systemd-resolved)
Edit `/etc/systemd/resolved.conf`:
```ini
[Resolve]
DNS=YOUR_SERVER_IP
```
Restart the service: `sudo systemctl restart systemd-resolved`
