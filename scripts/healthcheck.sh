#!/bin/bash
# BalanceDNS Health Check Script
# This script checks if the BalanceDNS server is responsive and restarts it if not.
#
# Usage: ./healthcheck.sh [--quiet]
#   --quiet: Suppress all output except errors

QUIET=false
if [[ "$1" == "--quiet" ]]; then
    QUIET=true
fi

# Configuration - adjust these values
DNS_SERVER="144.31.151.64"
DNS_PORT="53"
HEALTHCHECK_TIMEOUT=3
MAX_RETRIES=2
RETRY_DELAY=1
RESTART_COOLDOWN=10  # Minimum seconds between restarts
LOG_FILE="/var/log/balancedns-healthcheck.log"
PID_FILE="/run/balancedns.pid"

# Colors for output (disabled in quiet mode or non-interactive)
if [[ -t 1 && "$QUIET" == false ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$QUIET" == false ]]; then
        case "$level" in
            ERROR)   echo -e "${RED}[$timestamp] ERROR: $msg${NC}" ;;
            WARN)    echo -e "${YELLOW}[$timestamp] WARN: $msg${NC}" ;;
            OK)      echo -e "${GREEN}[$timestamp] OK: $msg${NC}" ;;
            INFO)    echo "[$timestamp] INFO: $msg" ;;
        esac
    fi
    
    # Always log to file
    echo "[$timestamp] $level: $msg" >> "$LOG_FILE" 2>/dev/null || true
}

# Check if the DNS server responds to a query
check_dns_responsive() {
    local attempt=$1
    
    # Use dig, nslookup, or host to test DNS resolution
    if command -v dig &> /dev/null; then
        local result
        result=$(dig +short +time=$HEALTHCHECK_TIMEOUT +tries=1 @${DNS_SERVER} -p ${DNS_PORT} localhost A 2>&1)
        if [[ $? -eq 0 ]]; then
            return 0
        fi
    elif command -v nslookup &> /dev/null; then
        local result
        result=$(nslookup localhost ${DNS_SERVER} ${DNS_PORT} 2>&1 | head -n 5)
        if [[ $? -eq 0 && ! "$result" =~ *"connection timed out"* ]]; then
            return 0
        fi
    elif command -v host &> /dev/null; then
        local result
        result=$(host -t A -W $HEALTHCHECK_TIMEOUT localhost ${DNS_SERVER} ${DNS_PORT} 2>&1)
        if [[ $? -eq 0 ]]; then
            return 0
        fi
    else
        # Fallback: try to connect to the port
        timeout $HEALTHCHECK_TIMEOUT bash -c "echo >/dev/tcp/${DNS_SERVER}/${DNS_PORT}" 2>/dev/null
        return $?
    fi
    
    return 1
}

# Check if the service is running
is_service_running() {
    systemctl is-active --quiet balancedns 2>/dev/null
    return $?
}

# Restart the service
restart_service() {
    log_msg "INFO" "Attempting to restart balancedns service..."
    
    # Check cooldown period (only if service was recently restarted, not if it's completely down)
    if [[ -f "$PID_FILE" ]] && is_service_running; then
        local last_restart
        last_restart=$(cat "$PID_FILE" 2>/dev/null || echo "0")
        local current_time
        current_time=$(date +%s)
        local time_since_restart=$((current_time - last_restart))
        
        if [[ $time_since_restart -lt $RESTART_COOLDOWN ]]; then
            log_msg "WARN" "Restart cooldown period active (${time_since_restart}s/${RESTART_COOLDOWN}s). Skipping restart."
            return 1
        fi
    fi
    
    # Update PID file with current timestamp
    date +%s > "$PID_FILE" 2>/dev/null || true
    
    if systemctl restart balancedns 2>/dev/null; then
        log_msg "OK" "Successfully restarted balancedns service"
        return 0
    else
        log_msg "ERROR" "Failed to restart balancedns service"
        return 1
    fi
}

# Check service health metrics via HTTP API (if enabled)
check_metrics_endpoint() {
    local metrics_url="http://127.0.0.1:9153/metrics"
    
    if command -v curl &> /dev/null; then
        local response
        response=$(curl -s --max-time 3 "$metrics_url" 2>/dev/null)
        if [[ $? -eq 0 && -n "$response" ]]; then
            # Extract some useful metrics
            local uptime
            uptime=$(echo "$response" | grep "balancedns_uptime_seconds" | awk '{print $2}')
            if [[ -n "$uptime" ]]; then
                log_msg "INFO" "Server uptime: ${uptime}s"
            fi
            
            local errors
            errors=$(echo "$response" | grep "balancedns_client_queries_errors_total" | awk '{print $2}')
            if [[ -n "$errors" ]]; then
                log_msg "INFO" "Total query errors: $errors"
            fi
            
            return 0
        fi
    fi
    
    return 1
}

# Main health check logic
main() {
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    
    log_msg "INFO" "Starting health check for ${DNS_SERVER}:${DNS_PORT}"
    
    # Check if service is running
    if ! is_service_running; then
        log_msg "ERROR" "balancedns service is not running"
        restart_service
        exit 1
    fi
    
    # Try to check metrics endpoint (optional, won't fail if unavailable)
    check_metrics_endpoint
    
    # Check DNS responsiveness with retries
    local is_responsive=false
    for attempt in $(seq 1 $MAX_RETRIES); do
        if check_dns_responsive $attempt; then
            is_responsive=true
            break
        fi
        
        if [[ $attempt -lt $MAX_RETRIES ]]; then
            log_msg "WARN" "Health check attempt $attempt failed, retrying in ${RETRY_DELAY}s..."
            sleep $RETRY_DELAY
        fi
    done
    
    if [[ "$is_responsive" == true ]]; then
        log_msg "OK" "BalanceDNS server is responsive on ${DNS_SERVER}:${DNS_PORT}"
        exit 0
    else
        log_msg "ERROR" "BalanceDNS server is NOT responding after $MAX_RETRIES attempts"
        
        # Attempt restart
        restart_service
        
        # Verify restart was successful
        sleep 2
        if check_dns_responsive 1; then
            log_msg "OK" "Server recovered after restart"
            exit 0
        else
            log_msg "ERROR" "Server still unresponsive after restart!"
            exit 1
        fi
    fi
}

# Run main function
main
