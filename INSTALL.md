# BalanceDNS - Quick Installation Guide

## 🚀 One-Command Installation

```bash
# Clone and install
git clone https://your-repo/BalanceDNS.git
cd BalanceDNS
sudo ./install.sh
```

That's it! The installer will:
1. ✅ Compile BalanceDNS from source
2. ✅ Create system user and directories
3. ✅ Generate configuration with your settings
4. ✅ Install systemd service with watchdog
5. ✅ Setup health check monitoring (every 30s)
6. ✅ Start and verify everything works

## 📋 Installer Options

```bash
# Full installation (interactive)
sudo ./install.sh

# Skip compilation (if you already built it)
sudo ./install.sh --skip-build

# Only update configuration
sudo ./install.sh --config-only
```

## 🔧 What the Installer Asks For

The installer will prompt for:
1. **Server IP** - Your server's public IP (default: auto-detected)
2. **Primary upstream DNS** - Main DNS resolver (default: 95.85.95.95)
3. **Secondary upstream DNS** - Backup DNS resolver (default: 2.56.220.2)
4. **Russian zone upstream** - For .ru domains (default: 77.88.8.8)

Just press Enter to accept defaults!

## 🛡️ What You Get

### Automatic Protection
- **Process crash** → Restarts in 2 seconds
- **Process hang** → Watchdog kills after 60s
- **DNS unresponsive** → Health check restarts after 30s
- **Memory limit** → 2GB max enforced
- **Connection limit** → 4096 max TCP clients

### Monitoring Scripts
```bash
# Quick status check
./scripts/status.sh

# Real-time monitoring dashboard
./scripts/monitor.sh

# View health check logs
tail -f /var/log/balancedns-healthcheck.log

# View service logs
journalctl -u balancedns -f
```

## 🔍 Testing Your Installation

```bash
# Test DNS resolution
dig @YOUR_IP google.com A

# Test Russian domains
dig @YOUR_IP ya.ru A

# Test with specific DNS server
nslookup google.com YOUR_IP
```

## ⚙️ Configuration

After installation, you can edit the config:

```bash
nano /etc/balancedns.toml
systemctl restart balancedns
```

### Key Settings

```toml
[server]
udp_listen = "YOUR_IP:53"
tcp_listen = "YOUR_IP:53"

[cache]
max_size = 100000  # Max cached entries
ttl_seconds = 7200 # Default TTL

[global]
max_tcp_clients = 4096  # Max simultaneous TCP
threads_udp = 8         # UDP worker threads
```

## 📊 Accessing Metrics

Prometheus metrics are available at:
```
http://127.0.0.1:9100/metrics
```

To expose them externally, add a reverse proxy or change `metrics.listen` in config.

## 🔄 Reinstallation

If you need to reinstall:

```bash
# Full reinstall (removes everything)
sudo ./uninstall.sh
sudo ./install.sh

# Keep config and data
sudo ./uninstall.sh --keep-config --keep-data
sudo ./install.sh --skip-build
```

## ❌ Uninstallation

```bash
# Remove everything
sudo ./uninstall.sh

# Keep configuration
sudo ./uninstall.sh --keep-config

# Keep configuration and data
sudo ./uninstall.sh --keep-config --keep-data
```

## 🆘 Troubleshooting

### Service won't start
```bash
# Check logs
journalctl -u balancedns -n 50 --no-pager

# Test configuration
/usr/sbin/balancedns --config /etc/balancedns.toml --test
```

### DNS not responding
```bash
# Check if listening on correct port
ss -tulpn | grep :53

# Test locally
dig @127.0.0.1 localhost A

# Check health check logs
tail -n 50 /var/log/balancedns-healthcheck.log
```

### Health check failing
```bash
# Run manually
/usr/local/bin/balancedns-healthcheck.sh

# Check timer status
systemctl status balancedns-healthcheck.timer
```

## 📁 Installed Files

```
/usr/sbin/balancedns                      # Main binary
/etc/balancedns.toml                      # Configuration
/var/lib/balancedns/                      # Data directory
  tls/server.crt                          # TLS certificate
  tls/server.key                          # TLS private key
/usr/local/bin/balancedns-healthcheck.sh  # Health check script
/var/log/balancedns-healthcheck.log       # Health check log
/etc/systemd/system/balancedns.service    # Service file
/etc/systemd/system/balancedns-healthcheck.timer  # Health check timer
```

## 🎯 Next Steps

1. **Test DNS resolution** - Make sure it works
2. **Update upstream servers** - Edit `/etc/balancedns.toml` if needed
3. **Configure firewall** - Allow UDP/TCP 53, TCP 853 (DoT), TCP 443 (DoH)
4. **Setup Prometheus** (optional) - Scrape metrics from `http://127.0.0.1:9100/metrics`

## 🔐 Firewall Configuration

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
sudo ufw allow 853/tcp  # DoT
sudo ufw allow 443/tcp  # DoH

# FirewallD (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=53/udp
sudo firewall-cmd --permanent --add-port=53/tcp
sudo firewall-cmd --permanent --add-port=853/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

---

**That's it! Your DNS server is now running with automatic monitoring and self-healing!** 🎉
