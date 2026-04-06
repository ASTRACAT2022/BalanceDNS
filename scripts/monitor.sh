#!/bin/bash
# BalanceDNS Monitor - Real-time monitoring dashboard
# Displays server status, metrics, and health information
#
# Usage: ./monitor.sh [--interval SECONDS]

INTERVAL=${1:-5}
METRICS_URL="http://127.0.0.1:9100/metrics"
DNS_SERVER="144.31.151.64"
DNS_PORT="53"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Clear screen and hide cursor
clear
tput civis

cleanup() {
    tput cnorm
    tput sgr0
    clear
    exit 0
}

trap cleanup SIGINT SIGTERM

# Get metric value by name
get_metric() {
    local name="$1"
    local metrics="$2"
    echo "$metrics" | grep "^${name}" | awk '{print $2}' | head -n 1
}

# Check DNS responsiveness
check_dns() {
    if command -v dig &> /dev/null; then
        local result
        result=$(dig +short +time=2 +tries=1 @${DNS_SERVER} -p ${DNS_PORT} localhost A 2>&1)
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}● Responsive${NC}"
            return 0
        fi
    fi
    echo -e "${RED}● Not Responding${NC}"
    return 1
}

# Check service status
check_service() {
    if systemctl is-active --quiet balancedns 2>/dev/null; then
        echo -e "${GREEN}● Active (running)${NC}"
        return 0
    else
        echo -e "${RED}● Inactive/Failed${NC}"
        return 1
    fi
}

# Format seconds to human readable
format_uptime() {
    local seconds=$1
    local days=$((seconds / 86400))
    local hours=$(( (seconds % 86400) / 3600 ))
    local minutes=$(( (seconds % 3600) / 60 ))
    
    if [[ $days -gt 0 ]]; then
        echo "${days}d ${hours}h ${minutes}m"
    elif [[ $hours -gt 0 ]]; then
        echo "${hours}h ${minutes}m"
    else
        echo "${minutes}m"
    fi
}

# Main display loop
while true; do
    # Fetch metrics
    metrics=""
    if command -v curl &> /dev/null; then
        metrics=$(curl -s --max-time 3 "$METRICS_URL" 2>/dev/null)
    fi

    # Start drawing
    tput cup 0 0

    # Header
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC}  ${BOLD}BalanceDNS Monitor${NC}                                      ${BOLD}${BLUE}║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Service Status
    echo -e "${BOLD}${CYAN}Service Status:${NC}"
    echo -e "  Service:      $(check_service)"
    echo -e "  DNS Server:   $(check_dns)"

    # Get service restart info
    if systemctl is-active --quiet balancedns 2>/dev/null; then
        restart_count=$(systemctl show balancedns --property=NRestarts 2>/dev/null | cut -d= -f2)
        echo -e "  Restarts:     ${YELLOW}${restart_count:-0}${NC}"
    fi
    echo ""

    # Metrics (if available)
    if [[ -n "$metrics" ]]; then
        echo -e "${BOLD}${CYAN}Query Statistics:${NC}"

        total_queries=$(get_metric "balancedns_client_queries_total" "$metrics")
        total_errors=$(get_metric "balancedns_client_queries_errors_total" "$metrics")
        inflight=$(get_metric "balancedns_inflight_queries" "$metrics")

        echo -e "  Total Queries:    ${GREEN}${total_queries:-0}${NC}"
        echo -e "  Total Errors:     ${RED}${total_errors:-0}${NC}"

        # Calculate error rate
        if [[ -n "$total_queries" && -n "$total_errors" && "$total_queries" != "0" ]]; then
            error_rate=$(awk "BEGIN {printf \"%.2f\", ($total_errors / $total_queries) * 100}")
            if (( $(echo "$error_rate > 5" | bc -l 2>/dev/null || echo "0") )); then
                echo -e "  Error Rate:       ${RED}${error_rate}%${NC}"
            else
                echo -e "  Error Rate:       ${GREEN}${error_rate}%${NC}"
            fi
        fi

        echo -e "  In-Flight:        ${YELLOW}${inflight:-0}${NC}"
        echo ""

        # Cache Statistics
        echo -e "${BOLD}${CYAN}Cache Statistics:${NC}"

        cache_hits=$(get_metric "balancedns_cache_hits_total" "$metrics")
        cache_misses=$(get_metric "balancedns_cache_misses_total" "$metrics")

        if [[ -n "$cache_hits" && -n "$cache_misses" ]]; then
            cache_total=$((cache_hits + cache_misses))
            hit_rate=$(awk "BEGIN {printf \"%.2f\", ($cache_hits / $cache_total) * 100}")
            echo -e "  Cache Hits:       ${GREEN}${cache_hits}${NC}"
            echo -e "  Cache Misses:     ${YELLOW}${cache_misses}${NC}"
            echo -e "  Hit Rate:         ${GREEN}${hit_rate}%${NC}"
        fi
        echo ""

        # Upstream Statistics
        echo -e "${BOLD}${CYAN}Upstream Statistics:${NC}"

        upstream_queries=$(get_metric "balancedns_upstream_queries_total" "$metrics")
        upstream_errors=$(get_metric "balancedns_upstream_errors_total" "$metrics")

        echo -e "  Upstream Queries: ${BLUE}${upstream_queries:-0}${NC}"
        echo -e "  Upstream Errors:    ${RED}${upstream_errors:-0}${NC}"
        echo ""

        # Connection Statistics
        echo -e "${BOLD}${CYAN}Connection Statistics:${NC}"

        tcp_connections=$(get_metric "balancedns_tcp_connections" "$metrics")
        echo -e "  Active TCP:       ${YELLOW}${tcp_connections:-0}${NC}"

        udp_queries=$(get_metric "balancedns_client_queries_udp_total" "$metrics")
        tcp_queries=$(get_metric "balancedns_client_queries_tcp_total" "$metrics")
        dot_queries=$(get_metric "balancedns_client_queries_dot_total" "$metrics")
        doh_queries=$(get_metric "balancedns_client_queries_doh_total" "$metrics")

        echo -e "  UDP Queries:      ${BLUE}${udp_queries:-0}${NC}"
        echo -e "  TCP Queries:      ${BLUE}${tcp_queries:-0}${NC}"
        echo -e "  DoT Queries:      ${BLUE}${dot_queries:-0}${NC}"
        echo -e "  DoH Queries:      ${BLUE}${doh_queries:-0}${NC}"
        echo ""

        # System Information
        echo -e "${BOLD}${CYAN}System Information:${NC}"

        uptime_seconds=$(get_metric "balancedns_uptime_seconds" "$metrics")
        if [[ -n "$uptime_seconds" ]]; then
            echo -e "  Uptime:           $(format_uptime ${uptime_seconds%.*})"
        fi

        memory_rss=$(get_metric "process_resident_memory_bytes" "$metrics")
        if [[ -n "$memory_rss" ]]; then
            memory_mb=$((memory_rss / 1024 / 1024))
            echo -e "  Memory (RSS):     ${YELLOW}${memory_mb} MB${NC}"
        fi

        file_descriptors=$(get_metric "process_open_fds" "$metrics")
        echo -e "  Open FDs:         ${YELLOW}${file_descriptors:-0}${NC}"
    else
        echo -e "${YELLOW}Metrics endpoint not available at ${METRICS_URL}${NC}"
        echo -e "Enable webservice in config to see detailed metrics."
    fi
    
    # Footer
    echo ""
    echo -e "${BLUE}──────────────────────────────────────────────────────────────────${NC}"
    echo -e "  Press ${BOLD}Ctrl+C${NC} to exit  |  Refresh: ${BOLD}${INTERVAL}s${NC}  |  $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${BLUE}──────────────────────────────────────────────────────────────────${NC}"
    
    sleep $INTERVAL
done
