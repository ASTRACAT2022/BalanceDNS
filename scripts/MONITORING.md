# BalanceDNS Monitoring & Auto-Restart System

## Overview

This monitoring system provides automatic health checking and restart capabilities for BalanceDNS:

1. **Systemd Restart Policy** - OS-level supervision with automatic restart on process exit/failure
2. **Health Check Timer** - Periodic UDP/DoH/DoT checks every 15 seconds
3. **Auto-Restart** - Automatic service restart if health checks fail
4. **Monitoring Dashboard** - Real-time metrics and status display
5. **Panic Recovery** - Application-level panic guards prevent crashes from killing the server

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BalanceDNS Server                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │  UDP     │  │  TCP     │  │  DoT     │  │  DoH       │ │
│  │ Workers  │  │ Sessions │  │ Sessions │  │  Sessions  │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘ │
│       └──────────────┴──────────────┴──────────────┘       │
│                          │                                  │
│              Panic Guards (catch_unwind)                   │
│                          │                                  │
└──────────────────────────┼──────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │  systemd Restart Policy │
              │   (Restart=always)      │
              └────────────┬────────────┘
                           │
              ┌────────────┴────────────┐
              │  Health Check Timer     │
              │  (every 15 seconds)     │
              └────────────┬────────────┘
                           │
              ┌────────────┴────────────┐
              │   Auto-Restart Logic    │
              │  (if health check fails)│
              └─────────────────────────┘
```

## Components

### 1. Systemd Service (balancedns.service)

**Key Features:**
- `Type=simple` - Standard long-running process mode
- `Restart=always` - Automatic restart if process exits/fails
- `Restart=always` - Automatic restart on any failure
- `RestartSec=2` - Wait 2 seconds before restarting
- Resource limits (memory, file descriptors, tasks)

**What it monitors:**
- Process crashes
- Unexpected process exits/failures
- OOM killer
- Signal-based termination

### 2. Health Check Timer (balancedns-healthcheck.timer)

**Key Features:**
- Runs every 15 seconds
- Tests UDP, DoH and DoT endpoints
- Retries 2 times before declaring failure
- Automatic service restart after consecutive failed runs
- Cooldown between restarts to prevent restart loops

**What it monitors:**
- UDP/DoH/DoT query responsiveness
- Service state (is it running?)
- Application-level responsiveness

### 3. Panic Recovery (Code Changes)

**Changes made:**
- `panic = "unwind"` instead of `panic = "abort"`
- All thread handlers wrapped with `catch_unwind()`
- Session timeouts prevent resource exhaustion
- Proper error handling instead of unwrap()

**What it prevents:**
- Single query crashes from killing the entire server
- Memory leaks from long-running sessions
- Thread exhaustion from connection floods

## Installation

### Quick Install

```bash
cd /root/BalanceDNS
sudo ./scripts/install-monitor.sh
```

### Manual Installation

1. **Copy health check script:**
```bash
sudo cp scripts/healthcheck.sh /usr/local/bin/balancedns-healthcheck.sh
sudo chmod +x /usr/local/bin/balancedns-healthcheck.sh
```

2. **Install systemd files:**
```bash
sudo cp balancedns-healthcheck.service /etc/systemd/system/
sudo cp balancedns-healthcheck.timer /etc/systemd/system/
sudo cp balancedns.service /etc/systemd/system/
sudo systemctl daemon-reload
```

3. **Enable and start:**
```bash
sudo systemctl enable balancedns-healthcheck.timer
sudo systemctl start balancedns-healthcheck.timer
sudo systemctl restart balancedns
```

## Usage

### Check Service Status

```bash
# Quick status
./scripts/status.sh

# Detailed service info
systemctl status balancedns
systemctl status balancedns-healthcheck.timer
```

### View Logs

```bash
# Health check logs
tail -f /var/log/balancedns-healthcheck.log

# Service logs
journalctl -u balancedns -f

# Health check service logs
journalctl -u balancedns-healthcheck.service -f
```

### Real-time Monitoring Dashboard

```bash
# Interactive monitoring (refreshes every 5 seconds)
./scripts/monitor.sh

# Custom refresh interval (10 seconds)
./scripts/monitor.sh 10
```

### Manual Health Check

```bash
# Run health check manually
/usr/local/bin/balancedns-healthcheck.sh

# Quiet mode (only errors)
/usr/local/bin/balancedns-healthcheck.sh --quiet
```

### Uninstall

```bash
sudo ./scripts/uninstall-monitor.sh
```

## Configuration

### Health Check Settings

Edit `/etc/default/balancedns-healthcheck`:

```bash
BALANCEDNS_CHECK_PROTOCOLS=udp,doh,dot
BALANCEDNS_DNS_SERVER=127.0.0.1
BALANCEDNS_DNS_PORT=53
BALANCEDNS_DOH_URL=https://127.0.0.1/dns-query
BALANCEDNS_DOT_PORT=853
BALANCEDNS_FAILURE_THRESHOLD=3
BALANCEDNS_RESTART_COOLDOWN=30
```

### Health Check Frequency

Edit `/etc/systemd/system/balancedns-healthcheck.timer`:

```ini
OnUnitActiveSec=15  # Change to adjust check frequency
```

Then run:
```bash
sudo systemctl daemon-reload
sudo systemctl restart balancedns-healthcheck.timer
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u balancedns -n 50 --no-pager

# Test config
balancedns --config /etc/balancedns.toml --test

# Check port conflicts
sudo ss -tulpn | grep :53
```

### Health Check Fails

```bash
# Test DNS manually
dig @127.0.0.1 localhost A

# Run health check with debug
bash -x /usr/local/bin/balancedns-healthcheck.sh

# Check health check logs
tail -n 100 /var/log/balancedns-healthcheck.log
```

### Too Many Restarts

Check for restart loops:

```bash
# Check restart count
systemctl show balancedns --property=NRestarts

# Check recent restarts
journalctl -u balancedns --since "1 hour ago" | grep -i "restart\|started"
```

If restart loops occur, increase `RESTART_COOLDOWN` in the health check script.

### Service Hangs

The healthcheck timer detects hangs where process is alive but requests are not served.
Check recent runs:

```bash
journalctl -u balancedns-healthcheck.service --since "15 minutes ago"
```

## Monitoring Metrics

The monitoring system tracks:

- **Query Statistics**: Total queries, errors, error rate
- **Cache Performance**: Hit rate, misses
- **Connection Status**: Active TCP connections
- **Protocol Breakdown**: UDP, TCP, DoT, DoH queries
- **System Resources**: Memory usage, file descriptors
- **Service Health**: Uptime, restart count

Access metrics via:
- **Prometheus**: http://127.0.0.1:9153/metrics
- **Dashboard**: `./scripts/monitor.sh`
- **Status**: `./scripts/status.sh`

## Advanced: Prometheus Alerting

Example Prometheus alerting rules:

```yaml
groups:
  - name: balancedns
    rules:
      - alert: BalanceDNSDown
        expr: up{job="balancedns"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "BalanceDNS is down"
          description: "BalanceDNS has been down for more than 1 minute"

      - alert: BalanceDNSHighErrorRate
        expr: rate(balancedns_client_queries_errors_total[5m]) / rate(balancedns_client_queries_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "BalanceDNS high error rate"
          description: "Error rate is above 5%"
```

## System Requirements

- systemd 232+ (for WatchdogSec)
- dig, nslookup, or host (for health checks)
- curl (for metrics collection)
- Bash 4.0+

## License

Same as BalanceDNS project.
