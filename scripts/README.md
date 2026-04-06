# BalanceDNS Monitoring System - Quick Start

## ✅ Installation Complete!

The monitoring system is now installed and running on your server.

## 📊 What's Installed

1. **Health Check Timer** - Checks DNS every 30 seconds
2. **Auto-Restart** - Restarts if server becomes unresponsive  
3. **Systemd Watchdog** - Kills & restarts if process hangs (60s timeout)
4. **Status Scripts** - Easy monitoring and status checking

## 🎯 Quick Commands

```bash
# Check status
/root/BalanceDNS/scripts/status.sh

# Real-time monitoring dashboard
/root/BalanceDNS/scripts/monitor.sh

# View health check logs
tail -f /var/log/balancedns-healthcheck.log

# View service logs
journalctl -u balancedns -f
```

## 📍 Your Configuration

- **DNS Server**: 0.0.0.0:53
- **Metrics**: http://127.0.0.1:9100/metrics
- **Health Check**: Every 30 seconds

## 🛡️ Protection Levels

| Issue | Detection | Action |
|-------|-----------|--------|
| Process crash | Immediate | Auto-restart (2s delay) |
| Process hang | 60 seconds | SIGABRT + restart |
| DNS unresponsive | 30 seconds | Health check restart |
| Memory leak | Monitored | 2GB limit enforced |
| Too many connections | Monitored | 256 task limit |

## 📝 Log Files

- **Health checks**: `/var/log/balancedns-healthcheck.log`
- **Service logs**: `journalctl -u balancedns`
- **Health check service**: `journalctl -u balancedns-healthcheck.service`

## ⚙️ Configuration

### Adjust health check frequency
Edit `/etc/systemd/system/balancedns-healthcheck.timer`:
```ini
OnUnitActiveSec=30  # Change to desired frequency
```
Then: `sudo systemctl daemon-reload && sudo systemctl restart balancedns-healthcheck.timer`

### Adjust watchdog timeout
Edit `/etc/systemd/system/balancedns.service`:
```ini
WatchdogSec=60  # Change timeout
```
Then: `sudo systemctl daemon-reload && sudo systemctl restart balancedns`

## ✅ Current Status

All systems operational:
- ✓ Service running
- ✓ DNS responding  
- ✓ Health checks enabled
- ✓ Monitoring active

## 🚨 Troubleshooting

**Service won't start?**
```bash
journalctl -u balancedns -n 50 --no-pager
```

**Too many restarts?**
```bash
systemctl show balancedns --property=NRestarts
```

**DNS not responding?**
```bash
dig @144.31.151.64 localhost A
```
