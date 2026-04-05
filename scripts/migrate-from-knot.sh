#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

KNOT_CONFIG="${KNOT_CONFIG:-/etc/knot-resolver/kresd.conf}"
OUTPUT_CONFIG="${OUTPUT_CONFIG:-${REPO_DIR}/balancedns.migrated.toml}"
DEPLOY=0
SERVICE_NAME="${SERVICE_NAME:-balancedns}"
SERVICE_USER="${SERVICE_USER:-balancedns}"
SERVICE_GROUP="${SERVICE_GROUP:-balancedns}"
BINARY_PATH="${BINARY_PATH:-/usr/sbin/balancedns}"
CLI_BINARY_PATH="${CLI_BINARY_PATH:-/usr/sbin/astracatdnscli}"
PLUGIN_DIR="${PLUGIN_DIR:-/usr/lib/balancedns/plugins}"
STATE_DIR="${STATE_DIR:-/var/lib/balancedns}"
CONFIG_PATH="${CONFIG_PATH:-/etc/balancedns.toml}"
RUN_TESTS="${RUN_TESTS:-0}"

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --knot-config <path>   Path to Knot Resolver config (default: ${KNOT_CONFIG})
  --output <path>        Output BalanceDNS config path (default: ${OUTPUT_CONFIG})
  --deploy               Run install-systemd-safe.sh after config generation
  --config-path <path>   Final installed config path when --deploy (default: ${CONFIG_PATH})
  --run-tests            Run cargo tests during install (sets RUN_TESTS=1)
  -h, --help             Show this help

Environment overrides for --deploy:
  SERVICE_NAME, SERVICE_USER, SERVICE_GROUP, BINARY_PATH, CLI_BINARY_PATH, PLUGIN_DIR, STATE_DIR
EOF
}

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

append_unique() {
    local arr_name="$1"
    local value="$2"
    local existing=""
    local found=0
    eval "for existing in \"\${${arr_name}[@]:-}\"; do
        if [ \"\$existing\" = \"\$value\" ]; then
            found=1
            break
        fi
    done"
    if [ "$found" -eq 1 ]; then
        return 0
    fi
    eval "${arr_name}+=(\"\$value\")"
}

colons_count() {
    printf '%s' "$1" | tr -cd ':' | wc -c | tr -d '[:space:]'
}

sanitize_name() {
    local value="$1"
    value="$(printf '%s' "$value" | tr '[:space:]/:@' '----' | tr -cd '[:alnum:]._-')"
    if [ -z "$value" ]; then
        value="upstream"
    fi
    printf '%s' "$value"
}

parse_udp_endpoint() {
    local token="$1"
    local host=""
    local port=""

    if [[ "$token" == *"@"* ]]; then
        host="${token%@*}"
        port="${token##*@}"
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            port="53"
        fi
        if [[ "$host" == *:* && "$host" != \[*\] ]]; then
            host="[${host}]"
        fi
        printf '%s:%s' "$host" "$port"
        return 0
    fi

    if [[ "$token" == \[*\]:* ]]; then
        printf '%s' "$token"
        return 0
    fi

    local cc
    cc="$(colons_count "$token")"
    if [ "$cc" -gt 1 ]; then
        printf '[%s]:53' "$token"
        return 0
    fi

    if [[ "$token" == *:* ]]; then
        printf '%s' "$token"
    else
        printf '%s:53' "$token"
    fi
}

parse_cache_entries() {
    local line="$1"
    local line_u
    line_u="$(printf '%s' "$line" | tr '[:lower:]' '[:upper:]')"

    if [[ "$line_u" =~ CACHE\.SIZE[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*\*[[:space:]]*([KMG]?B) ]]; then
        local n="${BASH_REMATCH[1]}"
        local unit="${BASH_REMATCH[2]}"
        local bytes="$n"
        case "$unit" in
            KB) bytes=$((n * 1024)) ;;
            MB) bytes=$((n * 1024 * 1024)) ;;
            GB) bytes=$((n * 1024 * 1024 * 1024)) ;;
            B) bytes=$n ;;
        esac
        local entries=$((bytes / 1024))
        if [ "$entries" -lt 20000 ]; then entries=20000; fi
        if [ "$entries" -gt 2000000 ]; then entries=2000000; fi
        printf '%s' "$entries"
        return 0
    fi

    if [[ "$line_u" =~ CACHE\.SIZE[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
        local raw="${BASH_REMATCH[1]}"
        local entries=$((raw / 1024))
        if [ "$entries" -lt 20000 ]; then entries=20000; fi
        if [ "$entries" -gt 2000000 ]; then entries=2000000; fi
        printf '%s' "$entries"
        return 0
    fi

    printf ''
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --knot-config)
                KNOT_CONFIG="$2"
                shift 2
                ;;
            --output)
                OUTPUT_CONFIG="$2"
                shift 2
                ;;
            --deploy)
                DEPLOY=1
                shift
                ;;
            --config-path)
                CONFIG_PATH="$2"
                shift 2
                ;;
            --run-tests)
                RUN_TESTS=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown argument: $1" >&2
                usage
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    if [ ! -f "$KNOT_CONFIG" ]; then
        echo "Knot config not found: $KNOT_CONFIG" >&2
        exit 1
    fi

    if grep -Eqi '^[[:space:]]*(server|zone|template|database|acl)[[:space:]]*:' "$KNOT_CONFIG"; then
        echo "Detected Knot DNS authoritative config. This migrator supports Knot Resolver (kresd) only." >&2
        exit 1
    fi

    local -a dns_listeners=()
    local -a tls_listeners=()
    local -a doh_listeners=()
    local -a udp_upstreams=()
    local -a doh_upstreams=()
    local cache_entries="100000"

    local line=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%--*}"
        line="$(trim "$line")"
        [ -z "$line" ] && continue

        if [[ "$line" == *"net.listen("* ]]; then
            local ip=""
            local port=""
            local kind="dns"
            ip="$(printf '%s' "$line" | sed -nE "s/.*net\.listen\([[:space:]]*['\"]([^'\"]+)['\"].*/\1/p")"
            port="$(printf '%s' "$line" | sed -nE "s/.*net\.listen\([[:space:]]*['\"][^'\"]+['\"][[:space:]]*,[[:space:]]*([0-9]+).*/\1/p")"
            kind="$(printf '%s' "$line" | sed -nE "s/.*kind[[:space:]]*=[[:space:]]*['\"]([^'\"]+)['\"].*/\1/p")"
            if [ -z "$kind" ]; then kind="dns"; fi
            if [ -n "$ip" ] && [ -n "$port" ]; then
                local listener="${ip}:${port}"
                case "$kind" in
                    dns|udp|tcp) append_unique dns_listeners "$listener" ;;
                    tls|dot) append_unique tls_listeners "$listener" ;;
                    doh2|doh|https|http) append_unique doh_listeners "$listener" ;;
                    *) append_unique dns_listeners "$listener" ;;
                esac
            fi
        fi

        if [[ "$line" == *"FORWARD("* || "$line" == *"STUB("* ]]; then
            local q=""
            while IFS= read -r q; do
                q="${q#\'}"; q="${q%\'}"
                q="${q#\"}"; q="${q%\"}"
                q="$(trim "$q")"
                [ -z "$q" ] && continue

                if [[ "$q" == http://* || "$q" == https://* ]]; then
                    append_unique doh_upstreams "$q"
                elif [[ "$q" =~ ^[A-Za-z0-9._-]+\.[A-Za-z]{2,}\.?$ && "$q" != *:* ]]; then
                    # likely a domain policy suffix, not an upstream endpoint
                    :
                else
                    append_unique udp_upstreams "$(parse_udp_endpoint "$q")"
                fi
            done < <(printf '%s\n' "$line" | grep -oE "\"[^\"]+\"|'[^']+'" || true)
        fi

        local parsed_cache=""
        parsed_cache="$(parse_cache_entries "$line")"
        if [ -n "$parsed_cache" ]; then
            cache_entries="$parsed_cache"
        fi
    done < "$KNOT_CONFIG"

    if [ "${#dns_listeners[@]}" -eq 0 ]; then
        dns_listeners=("0.0.0.0:53")
    fi
    if [ "${#udp_upstreams[@]}" -eq 0 ] && [ "${#doh_upstreams[@]}" -eq 0 ]; then
        udp_upstreams=("1.1.1.1:53" "8.8.8.8:53")
    fi

    local dns_addr="${dns_listeners[0]}"
    local dot_addr=""
    local doh_addr=""
    if [ "${#tls_listeners[@]}" -gt 0 ]; then dot_addr="${tls_listeners[0]}"; fi
    if [ "${#doh_listeners[@]}" -gt 0 ]; then doh_addr="${doh_listeners[0]}"; fi

    local cpu_cores
    cpu_cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '4')"
    local threads_udp=$((cpu_cores * 2))
    local threads_tcp=$((cpu_cores))
    if [ "$threads_udp" -lt 2 ]; then threads_udp=2; fi
    if [ "$threads_udp" -gt 64 ]; then threads_udp=64; fi
    if [ "$threads_tcp" -lt 1 ]; then threads_tcp=1; fi

    local output_dir
    output_dir="$(dirname "$OUTPUT_CONFIG")"
    mkdir -p "$output_dir"
    local tmp_config
    tmp_config="$(mktemp "${output_dir}/balancedns.toml.XXXXXX")"

    {
        echo "[server]"
        echo "udp_listen = \"${dns_addr}\""
        echo "tcp_listen = \"${dns_addr}\""
        if [ -n "$dot_addr" ]; then
            echo "dot_listen = \"${dot_addr}\""
        fi
        if [ -n "$doh_addr" ]; then
            echo "doh_listen = \"${doh_addr}\""
        fi

        if [ -n "$dot_addr" ] || [ -n "$doh_addr" ]; then
            echo
            echo "[tls]"
            echo "cert_pem = \"/var/lib/balancedns/tls/server.crt\""
            echo "key_pem = \"/var/lib/balancedns/tls/server.key\""
        fi

        echo
        echo "[balancing]"
        echo "algorithm = \"round_robin\""
        echo
        echo "[security]"
        echo "deny_any = true"
        echo "deny_dnskey = true"
        echo "request_timeout_ms = 800"
        echo
        echo "[cache]"
        echo "enabled = true"
        echo "max_size = ${cache_entries}"
        echo "ttl_seconds = 3600"
        echo "min_ttl = 30"
        echo "max_ttl = 86400"
        echo "decrement_ttl = true"
        echo "stale_refresh_enabled = true"
        echo "stale_ttl_seconds = 30"
        echo
        echo "[metrics]"
        echo "listen = \"127.0.0.1:9100\""
        echo
        echo "[hosts_local]"
        echo "# \"example.local.\" = \"192.168.1.100\""
        echo
        echo "[plugins]"
        echo "libraries = []"
        echo
        echo "[global]"
        echo "threads_udp = ${threads_udp}"
        echo "threads_tcp = ${threads_tcp}"
        echo "max_tcp_clients = 4096"
        echo "max_waiting_clients = 1000000"
        echo "max_active_queries = 200000"
        echo "max_clients_waiting_for_query = 2000"
    } > "$tmp_config"

    local -a all_upstream_names=()
    local idx=0
    local endpoint=""
    for endpoint in "${udp_upstreams[@]:-}"; do
        idx=$((idx + 1))
        local name
        name="$(sanitize_name "udp-${idx}-${endpoint}")"
        {
            echo
            echo "[[upstreams]]"
            echo "name = \"${name}\""
            echo "proto = \"udp\""
            echo "addr = \"${endpoint}\""
            echo "pool = \"default\""
            echo "weight = 5"
        } >> "$tmp_config"
        all_upstream_names+=("$name")
    done

    idx=0
    for endpoint in "${doh_upstreams[@]:-}"; do
        idx=$((idx + 1))
        local name
        name="$(sanitize_name "doh-${idx}")"
        {
            echo
            echo "[[upstreams]]"
            echo "name = \"${name}\""
            echo "proto = \"doh\""
            echo "url = \"${endpoint}\""
            echo "pool = \"default\""
            echo "weight = 5"
        } >> "$tmp_config"
        all_upstream_names+=("$name")
    done

    local joined=""
    local n=""
    for n in "${all_upstream_names[@]:-}"; do
        if [ -n "$joined" ]; then
            joined+=", "
        fi
        joined+="\"${n}\""
    done
    {
        echo
        echo "[[routing_rules]]"
        echo "suffix = \".\""
        echo "upstreams = [${joined}]"
    } >> "$tmp_config"

    mv -f "$tmp_config" "$OUTPUT_CONFIG"

    echo "Migration config generated: $OUTPUT_CONFIG"
    echo "Detected listeners: dns=${dns_addr} dot=${dot_addr:-disabled} doh=${doh_addr:-disabled}"
    echo "Detected upstreams: udp=${#udp_upstreams[@]} doh=${#doh_upstreams[@]}"
    echo "Estimated cache.max_size: ${cache_entries}"

    if [ "$DEPLOY" -ne 1 ]; then
        echo "Dry mode complete. To install now run:"
        echo "  ${REPO_DIR}/scripts/migrate-from-knot.sh --knot-config \"${KNOT_CONFIG}\" --output \"${OUTPUT_CONFIG}\" --deploy --config-path \"${CONFIG_PATH}\""
        exit 0
    fi

    echo "Starting deploy via install-systemd-safe.sh ..."
    if [ "$(id -u)" -eq 0 ]; then
        REPO_DIR="${REPO_DIR}" \
        SERVICE_NAME="${SERVICE_NAME}" \
        SERVICE_USER="${SERVICE_USER}" \
        SERVICE_GROUP="${SERVICE_GROUP}" \
        BINARY_PATH="${BINARY_PATH}" \
        CLI_BINARY_PATH="${CLI_BINARY_PATH}" \
        PLUGIN_DIR="${PLUGIN_DIR}" \
        STATE_DIR="${STATE_DIR}" \
        CONFIG_SOURCE="${OUTPUT_CONFIG}" \
        CONFIG_PATH="${CONFIG_PATH}" \
        OVERWRITE_CONFIG=1 \
        RUN_TESTS="${RUN_TESTS}" \
        "${REPO_DIR}/scripts/install-systemd-safe.sh"
    else
        sudo env \
            REPO_DIR="${REPO_DIR}" \
            SERVICE_NAME="${SERVICE_NAME}" \
            SERVICE_USER="${SERVICE_USER}" \
            SERVICE_GROUP="${SERVICE_GROUP}" \
            BINARY_PATH="${BINARY_PATH}" \
            CLI_BINARY_PATH="${CLI_BINARY_PATH}" \
            PLUGIN_DIR="${PLUGIN_DIR}" \
            STATE_DIR="${STATE_DIR}" \
            CONFIG_SOURCE="${OUTPUT_CONFIG}" \
            CONFIG_PATH="${CONFIG_PATH}" \
            OVERWRITE_CONFIG=1 \
            RUN_TESTS="${RUN_TESTS}" \
            "${REPO_DIR}/scripts/install-systemd-safe.sh"
    fi

    echo "Deploy complete."
    echo "Check status:"
    echo "  systemctl status ${SERVICE_NAME}"
    echo "  ${CLI_BINARY_PATH} watch -c ${CONFIG_PATH}"
}

main "$@"
