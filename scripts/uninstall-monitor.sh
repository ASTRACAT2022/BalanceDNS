#!/bin/bash
# BalanceDNS - Uninstall Monitoring System
# Usage: sudo ./uninstall-monitor.sh

set -e

echo "Uninstalling BalanceDNS Monitoring System..."
echo ""

# Stop and disable timer
echo "  [1/4] Stopping health check timer..."
systemctl stop balancedns-healthcheck.timer 2>/dev/null || true
systemctl disable balancedns-healthcheck.timer 2>/dev/null || true
echo "    ✓ Timer stopped and disabled"

# Remove systemd files
echo "  [2/4] Removing systemd files..."
rm -f /etc/systemd/system/balancedns-healthcheck.service
rm -f /etc/systemd/system/balancedns-healthcheck.timer
rm -f /etc/systemd/system/multi-user.target.wants/balancedns-healthcheck.timer
systemctl daemon-reload
echo "    ✓ Systemd files removed"

# Remove health check script
echo "  [3/4] Removing health check script..."
rm -f /usr/local/bin/balancedns-healthcheck.sh
echo "    ✓ Health check script removed"

# Remove log file (optional)
echo "  [4/4] Removing log file..."
rm -f /var/log/balancedns-healthcheck.log
echo "    ✓ Log file removed"

echo ""
echo "Monitoring system uninstalled successfully!"
echo "The main balancedns.service is still active."
