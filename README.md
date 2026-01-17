# 🐱 AstracatDNS Resolver

**A high-performance, secure, and privacy-focused DNS resolver.**

AstracatDNS is designed for speed and flexibility, featuring built-in AdBlock, local hosts overrides, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and automatic SSL certificate management. It is written in Go and optimized for modern deployment needs.

---

## ✨ Key Features

*   **🚀 High Performance**: Built on top of a fast, concurrent worker pool architecture.
*   **🛡️ AdBlock & Privacy**: Built-in AdBlock plugin that automatically downloads and updates blocklists (e.g., StevenBlack/hosts).
*   **🔒 Secure Protocols**:
    *   **DoH (DNS-over-HTTPS)**: Enabled by default on port 443.
    *   **DoT (DNS-over-TLS)**: Enabled by default on port 853.
    *   **DNSSEC**: Full validation support to ensure data integrity.
*   **📜 Automatic SSL**: Automatically generates and manages self-signed certificates for immediate secure deployment (valid for all local IPs and `0.0.0.0`).
*   **🔌 Plugins System**:
    *   **HostsPlugin**: Override domains using a local `hosts` file.
    *   **AdBlockPlugin**: Efficient memory-based domain blocking.
*   **📊 Observability**: Native Prometheus metrics exporter at `:9090/metrics`.
*   **🧠 Hybrid Caching**: Multi-level caching (L1 Memory + L2 BoltDB) with "Stale-While-Revalidate" support for instant answers.

---

## 🛠 Deployment

We provide a robust **local cross-compilation** script that builds the binary on your local machine (Mac/Linux) and uploads it to your server. This avoids dependency hell on the remote server.

### Prerequisites

*   **Local Machine**: Go 1.23+ installed.
*   **Remote Server**: Any Linux server (Debian/Ubuntu recommended) with SSH access. No Go installation required on the server!

### 🚀 One-Command Deploy

Use the `deploy_prod.sh` script to build, upload, and configure everything automatically.

**Syntax:**
```bash
./deploy_prod.sh [REMOTE_IP]
```

**Example:**
```bash
./deploy_prod.sh 192.168.1.50
```

**What this script does:**
1.  **Builds** the project locally for Linux (`amd64`).
2.  **Uploads** the optimized binary to the server.
3.  **Generates & Uploads** SSL certificates (in `certs/`) if they don't exist.
4.  **Configures** `systemd` to run AstracatDNS as a background service.
5.  **Restarts** the service and shows logs.

---

## ⚙️ Configuration

The system is configured via `config.yaml`.

```yaml
# Network
listen_addr: "0.0.0.0:53"
metrics_addr: "0.0.0.0:9090"
admin_addr: "0.0.0.0:8080"

# TLS (DoT / DoH)
dot_addr: "0.0.0.0:853"
doh_addr: "0.0.0.0:443"
cert_file: "certs/selfsigned.crt"
key_file: "certs/selfsigned.key"

# Caching
cache_size: 10000
cache_path: "cache/dns.db"
stale_while_revalidate: 1m

# Plugins
hosts_enabled: true
adblock_enabled: true
adblock_list_urls:
  - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
```

---

## 🖥 Local Usage

You can also run AstracatDNS locally on your Mac or Linux machine.

```bash
# Install dependencies
go mod tidy

# Run
go run main.go
```

The server will start on:
*   `localhost:53` (UDP/TCP DNS) - *Requires sudo if < 1024*
*   `localhost:443` (DoH)
*   `localhost:853` (DoT)
*   `localhost:9090` (Metrics)

---

## 📊 Metrics (Prometheus)

Metric | Description
--- | ---
`dns_resolver_qps` | Queries per second
`dns_resolver_total_queries` | Total incoming requests
`dns_resolver_cache_hits_total` | Responses served from cache
`dns_resolver_top_nx_domains` | Domains returning NXDOMAIN (often blocked ads)
`dns_resolver_dnssec_validation_total` | Validation results (Secure/Bogus/Insecure)

---

## 📜 License

MIT License. Created by the Astracat Team.
