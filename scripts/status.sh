#!/bin/bash
# BalanceDNS Quick Status Check
# Usage: ./status.sh

DNS_SERVER="144.31.151.64"
DNS_PORT="53"
METRICS_URL="http://127.0.0.1:9100/metrics"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BOLD}${BLUE}BalanceDNS Status Report${NC}"
echo -e "${BLUE}══════════════════════════════════════${NC}"
echo ""

# Service status
echo -e "${BOLD}Service Status:${NC}"
if systemctl is-active --quiet balancedns 2>/dev/null; then
    echo -e "  ● balancedns.service: ${GREEN}active (running)${NC}"
    
    # Get uptime
    start_time=$(systemctl show balancedns --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2-)
    if [[ -n "$start_time" ]]; then
        echo -e "    Started: $start_time"
    fi
else
    echo -e "  ● balancedns.service: ${RED}inactive/failed${NC}"
fi
echo ""

# DNS responsiveness
echo -e "${BOLD}DNS Responsiveness:${NC}"
if command -v dig &> /dev/null; then
    result=$(dig +short +time=2 +tries=1 @${DNS_SERVER} -p ${DNS_PORT} localhost A 2>&1)
    if [[ $? -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC} DNS server is responding on ${DNS_SERVER}:${DNS_PORT}"
    else
        echo -e "  ${RED}✗${NC} DNS server is NOT responding"
    fi
else
    echo -e "  ${YELLOW}!${NC} dig not installed - cannot test DNS responsiveness"
fi
echo ""

# Recent logs
echo -e "${BOLD}Recent Log Entries (last 10):${NC}"
journalctl -u balancedns --no-pager -n 10 2>/dev/null | tail -n 10 | while read line; do
    echo -e "  $line"
done
echo ""

# Metrics (if available)
if command -v curl &> /dev/null; then
    metrics=$(curl -s --max-time 2 "$METRICS_URL" 2>/dev/null)
    if [[ -n "$metrics" ]]; then
        echo -e "${BOLD}Quick Metrics:${NC}"
        
        total_queries=$(echo "$metrics" | grep "balancedns_client_queries_total" | awk '{print $2}')
        total_errors=$(echo "$metrics" | grep "balancedns_client_queries_errors_total" | awk '{print $2}')
        tcp_conn=$(echo "$metrics" | grep "balancedns_tcp_connections" | awk '{print $2}')
        
        echo -e "  Total Queries:  ${total_queries:-0}"
        echo -e "  Total Errors:   ${total_errors:-0}"
        echo -e "  TCP Connections: ${tcp_conn:-0}"
        echo ""
    fi
fi

# Check health check status
if systemctl is-active --quiet balancedns-healthcheck.timer 2>/dev/null; then
    echo -e "${BOLD}Health Check:${NC} ${GREEN}enabled${NC}"
    last_run=$(systemctl show balancedns-healthcheck.service --property=InactiveEnterTimestamp 2>/dev/null | cut -d= -f2-)
    if [[ -n "$last_run" && "$last_run" != "" ]]; then
        echo -e "  Last Check: $last_run"
    fi
else
    echo -e "${BOLD}Health Check:${NC} ${YELLOW}not enabled${NC}"
    echo -e "  Run: systemctl enable --now balancedns-healthcheck.timer"
fi

echo ""
echo -e "${BLUE}══════════════════════════════════════${NC}"
echo -e "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
