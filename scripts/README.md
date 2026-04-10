# BalanceDNS Monitoring System - Quick Start

## ✅ Installation Complete!

The monitoring system is now installed and running on your server.

## 📊 What's Installed

1. **Health Check Timer** - Checks UDP/DoH/DoT every 15 seconds
2. **Auto-Restart** - Restarts if server becomes unresponsive  
3. **Consecutive Failure Guard** - Restarts only after repeated failures
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
- **Health Check**: Every 15 seconds

## 🛡️ Protection Levels

| Issue | Detection | Action |
|-------|-----------|--------|
| Process crash | Immediate | Auto-restart (2s delay) |
| Process alive but not serving DoH/DoT | 15-45 seconds | Health check restart |
| Single transient network glitch | Immediate | No restart (failure threshold) |
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
OnUnitActiveSec=15  # Change to desired frequency
```
Then: `sudo systemctl daemon-reload && sudo systemctl restart balancedns-healthcheck.timer`

### Adjust healthcheck strategy
Edit `/etc/default/balancedns-healthcheck`:
```bash
BALANCEDNS_CHECK_PROTOCOLS=udp,doh,dot
BALANCEDNS_FAILURE_THRESHOLD=3
```
Then: `sudo systemctl restart balancedns-healthcheck.timer`

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
dig @127.0.0.1 localhost A
```
