#!/usr/bin/env bash
# BalanceDNS Health Check Script
#
# Checks service responsiveness and auto-restores it when the process is alive
# but no longer serving DNS traffic.
#
# Usage: ./healthcheck.sh [--quiet]
#
# Important environment variables:
#   BALANCEDNS_CHECK_PROTOCOLS=udp,doh,dot
#   BALANCEDNS_FAILURE_THRESHOLD=3
#   BALANCEDNS_DNS_SERVER=127.0.0.1
#   BALANCEDNS_DNS_PORT=53
#   BALANCEDNS_DOH_URL=https://127.0.0.1/dns-query
#   BALANCEDNS_DOH_INSECURE=true
#   BALANCEDNS_DOT_SERVER=127.0.0.1
#   BALANCEDNS_DOT_PORT=853

set -u

QUIET=false
if [[ "${1:-}" == "--quiet" ]]; then
    QUIET=true
fi

SERVICE_NAME="${BALANCEDNS_SERVICE_NAME:-balancedns}"
DNS_SERVER="${BALANCEDNS_DNS_SERVER:-127.0.0.1}"
DNS_PORT="${BALANCEDNS_DNS_PORT:-53}"
DOH_URL="${BALANCEDNS_DOH_URL:-https://127.0.0.1/dns-query}"
DOH_INSECURE="${BALANCEDNS_DOH_INSECURE:-true}"
DOT_SERVER="${BALANCEDNS_DOT_SERVER:-$DNS_SERVER}"
DOT_PORT="${BALANCEDNS_DOT_PORT:-853}"
DOT_SNI="${BALANCEDNS_DOT_SNI:-$DOT_SERVER}"
HEALTHCHECK_DOMAIN="${BALANCEDNS_HEALTHCHECK_DOMAIN:-example.com}"
CHECK_PROTOCOLS="${BALANCEDNS_CHECK_PROTOCOLS:-udp,doh,dot}"
METRICS_URL="${BALANCEDNS_METRICS_URL:-http://127.0.0.1:9100/metrics}"

HEALTHCHECK_TIMEOUT="${BALANCEDNS_HEALTHCHECK_TIMEOUT:-3}"
MAX_RETRIES="${BALANCEDNS_MAX_RETRIES:-2}"
RETRY_DELAY="${BALANCEDNS_RETRY_DELAY:-1}"
FAILURE_THRESHOLD="${BALANCEDNS_FAILURE_THRESHOLD:-3}"
RESTART_COOLDOWN="${BALANCEDNS_RESTART_COOLDOWN:-30}"

LOG_FILE="${BALANCEDNS_LOG_FILE:-/var/log/balancedns-healthcheck.log}"
STATE_FILE="${BALANCEDNS_STATE_FILE:-/run/balancedns-healthcheck.state}"
LOCK_FILE="${BALANCEDNS_LOCK_FILE:-/run/balancedns-healthcheck.lock}"

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

fail_count=0
last_restart=0

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    if [[ "$QUIET" == false ]]; then
        case "$level" in
            ERROR) echo -e "${RED}[$timestamp] ERROR: $msg${NC}" ;;
            WARN) echo -e "${YELLOW}[$timestamp] WARN: $msg${NC}" ;;
            OK) echo -e "${GREEN}[$timestamp] OK: $msg${NC}" ;;
            *) echo "[$timestamp] INFO: $msg" ;;
        esac
    fi

    echo "[$timestamp] $level: $msg" >>"$LOG_FILE" 2>/dev/null || true
}

is_true() {
    case "${1,,}" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

is_protocol_enabled() {
    local protocol="$1"
    local normalized=",${CHECK_PROTOCOLS,,},"
    [[ "$normalized" == *",$protocol,"* ]]
}

load_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        return
    fi
    while IFS='=' read -r key value; do
        case "$key" in
            fail_count)
                [[ "$value" =~ ^[0-9]+$ ]] && fail_count="$value"
                ;;
            last_restart)
                [[ "$value" =~ ^[0-9]+$ ]] && last_restart="$value"
                ;;
        esac
    done <"$STATE_FILE"
}

save_state() {
    umask 0077
    {
        echo "fail_count=$fail_count"
        echo "last_restart=$last_restart"
    } >"$STATE_FILE"
}

acquire_lock() {
    exec 9>"$LOCK_FILE"
    if command -v flock >/dev/null 2>&1; then
        if ! flock -n 9; then
            log_msg "WARN" "Another healthcheck run is still active, skipping"
            exit 0
        fi
    fi
}

is_service_running() {
    systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null
}

check_udp_responsive() {
    local output=""

    if command -v dig >/dev/null 2>&1; then
        output=$(
            dig +short +time="$HEALTHCHECK_TIMEOUT" +tries=1 \
                @"$DNS_SERVER" -p "$DNS_PORT" "$HEALTHCHECK_DOMAIN" A 2>/dev/null
        ) || true
        [[ -n "$output" ]] && return 0
    elif command -v nslookup >/dev/null 2>&1; then
        output=$(
            nslookup -timeout="$HEALTHCHECK_TIMEOUT" -port="$DNS_PORT" \
                "$HEALTHCHECK_DOMAIN" "$DNS_SERVER" 2>/dev/null
        ) || true
        [[ "$output" == *"Address:"* ]] && return 0
    elif command -v host >/dev/null 2>&1; then
        output=$(
            host -W "$HEALTHCHECK_TIMEOUT" -t A "$HEALTHCHECK_DOMAIN" \
                "$DNS_SERVER" 2>/dev/null
        ) || true
        [[ "$output" == *"has address"* ]] && return 0
    else
        timeout "$HEALTHCHECK_TIMEOUT" bash -c \
            "echo >/dev/udp/${DNS_SERVER}/${DNS_PORT}" >/dev/null 2>&1
        return $?
    fi

    return 1
}

build_test_dns_query() {
    # Standard DNS query for example.com A
    printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
}

check_doh_responsive() {
    [[ -z "$DOH_URL" ]] && return 0
    command -v curl >/dev/null 2>&1 || return 1

    local body_file
    local response_file
    body_file=$(mktemp /tmp/balancedns-doh-body.XXXXXX)
    response_file=$(mktemp /tmp/balancedns-doh-response.XXXXXX)
    build_test_dns_query >"$body_file"

    local curl_args=(
        -sS
        --max-time "$HEALTHCHECK_TIMEOUT"
        --connect-timeout "$HEALTHCHECK_TIMEOUT"
        -o "$response_file"
        -w '%{http_code}'
        -X POST
        -H 'accept: application/dns-message'
        -H 'content-type: application/dns-message'
        --data-binary "@${body_file}"
        "$DOH_URL"
    )
    if is_true "$DOH_INSECURE"; then
        curl_args=(-k "${curl_args[@]}")
    fi

    local http_code
    http_code=$(curl "${curl_args[@]}" 2>/dev/null || true)
    local body_size=0
    if [[ -f "$response_file" ]]; then
        body_size=$(wc -c <"$response_file" 2>/dev/null || echo 0)
    fi

    rm -f "$body_file" "$response_file"

    [[ "$http_code" == "200" && "$body_size" -ge 12 ]]
}

check_dot_responsive() {
    command -v kdig >/dev/null 2>&1 && {
        local output
        output=$(
            kdig +tls @"$DOT_SERVER" -p "$DOT_PORT" +time="$HEALTHCHECK_TIMEOUT" \
                "$HEALTHCHECK_DOMAIN" A +short 2>/dev/null
        ) || true
        [[ -n "$output" ]] && return 0
    }

    command -v openssl >/dev/null 2>&1 || return 1

    local response_prefix
    response_prefix=$(
        {
            # 0x001d length prefix + DNS query bytes
            printf '\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
            sleep 0.1
        } | timeout "$HEALTHCHECK_TIMEOUT" \
            openssl s_client -quiet \
                -connect "${DOT_SERVER}:${DOT_PORT}" \
                -servername "$DOT_SNI" \
                2>/dev/null | dd bs=2 count=1 status=none | xxd -p
    ) || true

    [[ "${#response_prefix}" -eq 4 ]]
}

check_protocol_once() {
    local protocol="$1"
    case "$protocol" in
        udp) check_udp_responsive ;;
        doh) check_doh_responsive ;;
        dot) check_dot_responsive ;;
        *) return 0 ;;
    esac
}

check_protocol_with_retries() {
    local protocol="$1"
    local attempt
    for attempt in $(seq 1 "$MAX_RETRIES"); do
        if check_protocol_once "$protocol"; then
            log_msg "OK" "Health check passed for protocol=${protocol}"
            return 0
        fi
        if [[ "$attempt" -lt "$MAX_RETRIES" ]]; then
            log_msg "WARN" "Health check failed for protocol=${protocol}, retry ${attempt}/${MAX_RETRIES}"
            sleep "$RETRY_DELAY"
        fi
    done
    return 1
}

check_metrics_endpoint() {
    command -v curl >/dev/null 2>&1 || return 1
    local response
    response=$(curl -sS --max-time 2 "$METRICS_URL" 2>/dev/null || true)
    [[ -z "$response" ]] && return 1

    local uptime
    uptime=$(echo "$response" | awk '/^balancedns_uptime(\{.*\})?[[:space:]]/ {print $2; exit}')
    [[ -n "$uptime" ]] && log_msg "INFO" "Metric uptime=${uptime}s"
    return 0
}

restart_service() {
    local now
    now=$(date +%s)

    if (( now - last_restart < RESTART_COOLDOWN )); then
        log_msg "WARN" "Restart cooldown active (${now-last_restart}s/${RESTART_COOLDOWN}s), restart skipped"
        return 1
    fi

    log_msg "WARN" "Restarting service ${SERVICE_NAME} due to repeated healthcheck failures"
    if systemctl restart "$SERVICE_NAME" 2>/dev/null; then
        last_restart="$now"
        fail_count=0
        save_state
        log_msg "OK" "Service ${SERVICE_NAME} restarted"
        return 0
    fi

    log_msg "ERROR" "Unable to restart service ${SERVICE_NAME}"
    return 1
}

main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    acquire_lock
    load_state

    log_msg "INFO" "Healthcheck started protocols=${CHECK_PROTOCOLS} target=${DNS_SERVER}:${DNS_PORT}"

    if ! is_service_running; then
        log_msg "ERROR" "Service ${SERVICE_NAME} is not active"
        ((fail_count++))
        save_state
        if (( fail_count >= FAILURE_THRESHOLD )); then
            restart_service
        fi
        exit 1
    fi

    check_metrics_endpoint || true

    local failed_protocols=()
    if is_protocol_enabled "udp"; then
        check_protocol_with_retries "udp" || failed_protocols+=("udp")
    fi
    if is_protocol_enabled "doh"; then
        check_protocol_with_retries "doh" || failed_protocols+=("doh")
    fi
    if is_protocol_enabled "dot"; then
        check_protocol_with_retries "dot" || failed_protocols+=("dot")
    fi

    if [[ "${#failed_protocols[@]}" -eq 0 ]]; then
        if (( fail_count > 0 )); then
            log_msg "OK" "Service recovered, resetting failure counter"
        fi
        fail_count=0
        save_state
        exit 0
    fi

    ((fail_count++))
    save_state
    log_msg "ERROR" "Failed protocols: ${failed_protocols[*]} (consecutive_failures=${fail_count}/${FAILURE_THRESHOLD})"

    if (( fail_count < FAILURE_THRESHOLD )); then
        exit 1
    fi

    restart_service || exit 1
    sleep 2

    local post_restart_failed=()
    if is_protocol_enabled "udp"; then
        check_protocol_once "udp" || post_restart_failed+=("udp")
    fi
    if is_protocol_enabled "doh"; then
        check_protocol_once "doh" || post_restart_failed+=("doh")
    fi
    if is_protocol_enabled "dot"; then
        check_protocol_once "dot" || post_restart_failed+=("dot")
    fi

    if [[ "${#post_restart_failed[@]}" -eq 0 ]]; then
        log_msg "OK" "Service is healthy after restart"
        exit 0
    fi

    log_msg "ERROR" "Service still unhealthy after restart: ${post_restart_failed[*]}"
    exit 1
}

main
