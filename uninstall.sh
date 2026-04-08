#!/bin/bash
###############################################################################
# BalanceDNS - Complete Uninstaller
# 
# Usage: sudo ./uninstall.sh [--keep-config] [--keep-data]
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

# Parse arguments
KEEP_CONFIG=false
KEEP_DATA=false
for arg in "$@"; do
    case $arg in
        --keep-config) KEEP_CONFIG=true ;;
        --keep-data) KEEP_DATA=true ;;
    esac
done

echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC}  ${BOLD}BalanceDNS Uninstaller${NC}                                    ${RED}║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}✗ This script must be run as root (use sudo)${NC}"
    exit 1
fi

read -p "Are you sure you want to uninstall BalanceDNS? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

echo ""
echo -e "${YELLOW}Stopping services...${NC}"
systemctl stop balancedns-healthcheck.timer 2>/dev/null || true
systemctl stop balancedns.service 2>/dev/null || true
systemctl disable balancedns.service 2>/dev/null || true
systemctl disable balancedns-healthcheck.timer 2>/dev/null || true
systemctl daemon-reload
echo -e "${GREEN}✓${NC} Services stopped and disabled"

echo ""
echo -e "${YELLOW}Removing systemd files...${NC}"
rm -f /etc/systemd/system/balancedns.service
rm -f /etc/systemd/system/balancedns-healthcheck.service
rm -f /etc/systemd/system/balancedns-healthcheck.timer
rm -f /etc/systemd/system/multi-user.target.wants/balancedns.service
rm -f /etc/systemd/system/timers.target.wants/balancedns-healthcheck.timer
systemctl daemon-reload
echo -e "${GREEN}✓${NC} Systemd files removed"

echo ""
echo -e "${YELLOW}Removing binary...${NC}"
rm -f /usr/sbin/balancedns
echo -e "${GREEN}✓${NC} Binary removed"

echo ""
echo -e "${YELLOW}Removing monitoring scripts...${NC}"
rm -f /usr/local/bin/balancedns-healthcheck.sh
echo -e "${GREEN}✓${NC} Monitoring scripts removed"

if [[ "$KEEP_CONFIG" == false ]]; then
    echo ""
    echo -e "${YELLOW}Removing configuration...${NC}"
    rm -f /etc/balancedns.lua
    rm -f /etc/balancedns.lua.bak.*
    rm -f /etc/balancedns.toml
    rm -f /etc/balancedns.toml.bak.*
    echo -e "${GREEN}✓${NC} Configuration removed"
else
    echo ""
    echo -e "${YELLOW}Keeping configuration files${NC}"
fi

if [[ "$KEEP_DATA" == false ]]; then
    echo ""
    echo -e "${YELLOW}Removing data directory...${NC}"
    rm -rf /var/lib/balancedns
    echo -e "${GREEN}✓${NC} Data directory removed"
    
    echo ""
    echo -e "${YELLOW}Removing logs...${NC}"
    rm -f /var/log/balancedns-healthcheck.log
    echo -e "${GREEN}✓${NC} Logs removed"
else
    echo ""
    echo -e "${YELLOW}Keeping data and logs${NC}"
fi

echo ""
echo -e "${YELLOW}Removing system user...${NC}"
if id "balancedns" &>/dev/null; then
    userdel balancedns 2>/dev/null || true
    echo -e "${GREEN}✓${NC} User removed"
else
    echo -e "${GREEN}✓${NC} User already removed"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  ${BOLD}Uninstallation Complete!${NC}                                  ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "BalanceDNS has been completely removed from your system."
echo ""
