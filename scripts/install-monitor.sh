#!/bin/bash
# BalanceDNS - Install Monitoring System
# This script installs the health check and monitoring system
#
# Usage: sudo ./install-monitor.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Installing BalanceDNS Monitoring System...${NC}"
echo ""

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Step 1: Install health check script
echo -e "  [1/5] Installing health check script..."
if [[ -f "$SCRIPT_DIR/healthcheck.sh" ]]; then
    cp "$SCRIPT_DIR/healthcheck.sh" /usr/local/bin/balancedns-healthcheck.sh
    chmod +x /usr/local/bin/balancedns-healthcheck.sh
    echo -e "        ${GREEN}✓${NC} Installed to /usr/local/bin/balancedns-healthcheck.sh"
else
    echo -e "        ${RED}✗${NC} healthcheck.sh not found in $SCRIPT_DIR"
    exit 1
fi

# Step 2: Install systemd timer and service
echo -e "  [2/5] Installing systemd health check timer..."
if [[ -f "$SCRIPT_DIR/../balancedns-healthcheck.service" ]]; then
    cp "$SCRIPT_DIR/../balancedns-healthcheck.service" /etc/systemd/system/
    echo -e "        ${GREEN}✓${NC} Installed balancedns-healthcheck.service"
else
    echo -e "        ${RED}✗${NC} balancedns-healthcheck.service not found"
    exit 1
fi

if [[ -f "$SCRIPT_DIR/../balancedns-healthcheck.timer" ]]; then
    cp "$SCRIPT_DIR/../balancedns-healthcheck.timer" /etc/systemd/system/
    echo -e "        ${GREEN}✓${NC} Installed balancedns-healthcheck.timer"
else
    echo -e "        ${RED}✗${NC} balancedns-healthcheck.timer not found"
    exit 1
fi

# Step 3: Update main service file
echo -e "  [3/5] Updating main balancedns.service..."
if [[ -f "$SCRIPT_DIR/../balancedns.service" ]]; then
    cp "$SCRIPT_DIR/../balancedns.service" /etc/systemd/system/balancedns.service
    echo -e "        ${GREEN}✓${NC} Updated balancedns.service"
else
    echo -e "        ${YELLOW}!${NC} balancedns.service not found - skipping"
fi

# Step 4: Create log directory
echo -e "  [4/5] Creating log directory..."
mkdir -p /var/log
touch /var/log/balancedns-healthcheck.log
chmod 644 /var/log/balancedns-healthcheck.log
echo -e "        ${GREEN}✓${NC} Log file created at /var/log/balancedns-healthcheck.log"

# Step 5: Enable and start services
echo -e "  [5/5] Enabling and starting services..."
systemctl daemon-reload
systemctl enable balancedns-healthcheck.timer
systemctl start balancedns-healthcheck.timer
echo -e "        ${GREEN}✓${NC} Health check timer enabled and started"

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}Monitoring system installed successfully!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "Installed components:"
echo -e "  ${BLUE}•${NC} Health check script: /usr/local/bin/balancedns-healthcheck.sh"
echo -e "  ${BLUE}•${NC} Health check timer: balancedns-healthcheck.timer (runs every 30s)"
echo -e "  ${BLUE}•${NC} Health check log:  /var/log/balancedns-healthcheck.log"
echo ""
echo -e "Useful commands:"
echo -e "  ${YELLOW}Check status:${NC}        systemctl status balancedns-healthcheck.timer"
echo -e "  ${YELLOW}View logs:${NC}           tail -f /var/log/balancedns-healthcheck.log"
echo -e "  ${YELLOW}Run monitor:${NC}         $SCRIPT_DIR/monitor.sh"
echo -e "  ${YELLOW}Quick status:${NC}        $SCRIPT_DIR/status.sh"
echo ""
echo -e "Health check will automatically restart balancedns if it becomes unresponsive."
