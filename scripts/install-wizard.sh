#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

prompt_default() {
    local prompt="$1"
    local default="$2"
    local value=""
    read -r -p "${prompt} [${default}]: " value || true
    value="$(trim "${value:-}")"
    if [ -z "$value" ]; then
        value="$default"
    fi
    printf '%s' "$value"
}

prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local value=""
    local default_hint="[y/N]"
    if [ "$default" = "yes" ]; then
        default_hint="[Y/n]"
    fi
    while true; do
        read -r -p "${prompt} ${default_hint}: " value || true
        value="$(trim "${value:-}")"
        value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
        if [ -z "$value" ]; then
            value="$default"
        fi
        case "$value" in
            y|yes) printf 'yes'; return 0 ;;
            n|no) printf 'no'; return 0 ;;
            *) printf 'Please enter yes/y or no/n\n' ;;
        esac
    done
}

split_csv_trimmed() {
    local source="$1"
    local -a raw_items=()
    IFS=',' read -r -a raw_items <<< "$source"
    for raw_item in "${raw_items[@]:-}"; do
        local item
        item="$(trim "$raw_item")"
        if [ -n "$item" ]; then
            printf '%s\n' "$item"
        fi
    done
}

join_toml_string_array() {
    local -a items=("$@")
    local out=""
    local item=""
    for item in "${items[@]}"; do
        if [ -n "$out" ]; then
            out+=", "
        fi
        out+="\"${item}\""
    done
    printf '%s' "$out"
}

detect_cpu_cores() {
    getconf _NPROCESSORS_ONLN 2>/dev/null || printf '4'
}

sanitize_name() {
    local value="$1"
    value="$(printf '%s' "$value" | tr '[:space:]' '-' | tr -cd '[:alnum:]._-')"
    if [ -z "$value" ]; then
        value="upstream"
    fi
    printf '%s' "$value"
}

append_upstream_block() {
    local file_path="$1"
    local name="$2"
    local proto="$3"
    local endpoint="$4"
    local weight="$5"
    {
        printf '\n[[upstreams]]\n'
        printf 'name = "%s"\n' "$name"
        printf 'proto = "%s"\n' "$proto"
        if [ "$proto" = "udp" ]; then
            printf 'addr = "%s"\n' "$endpoint"
        else
            printf 'url = "%s"\n' "$endpoint"
        fi
        printf 'pool = "default"\n'
        printf 'weight = %s\n' "$weight"
    } >> "$file_path"
}

parse_endpoint_weight() {
    local item="$1"
    local default_weight="$2"
    local endpoint="$item"
    local weight="$default_weight"
    if [[ "$item" == *@* ]]; then
        endpoint="${item%@*}"
        weight="${item##*@}"
    fi
    endpoint="$(trim "$endpoint")"
    weight="$(trim "$weight")"
    if ! [[ "$weight" =~ ^[0-9]+$ ]]; then
        weight="$default_weight"
    fi
    if [ "$weight" -eq 0 ]; then
        weight=1
    fi
    printf '%s;%s' "$endpoint" "$weight"
}

main() {
    printf 'BalanceDNS install wizard\n'
    printf 'This wizard builds config + can install and deploy automatically.\n\n'

    local generated_config_path
    generated_config_path="$(prompt_default "Generated config path" "${REPO_DIR}/balancedns.generated.toml")"

    local listen_ip
    listen_ip="$(prompt_default "DNS listen IP" "0.0.0.0")"
    local udp_port
    udp_port="$(prompt_default "UDP port" "53")"
    local tcp_port
    tcp_port="$(prompt_default "TCP port" "53")"

    local enable_dot
    enable_dot="$(prompt_yes_no "Enable DoT listener" "yes")"
    local dot_port="853"
    if [ "$enable_dot" = "yes" ]; then
        dot_port="$(prompt_default "DoT port" "853")"
    fi

    local enable_doh
    enable_doh="$(prompt_yes_no "Enable DoH listener" "yes")"
    local doh_port="443"
    if [ "$enable_doh" = "yes" ]; then
        doh_port="$(prompt_default "DoH port" "443")"
    fi

    local tls_cert_pem="/var/lib/balancedns/tls/server.crt"
    local tls_key_pem="/var/lib/balancedns/tls/server.key"
    if [ "$enable_dot" = "yes" ] || [ "$enable_doh" = "yes" ]; then
        tls_cert_pem="$(prompt_default "TLS cert path (cert_pem)" "$tls_cert_pem")"
        tls_key_pem="$(prompt_default "TLS key path (key_pem)" "$tls_key_pem")"
    fi

    local request_timeout_ms
    request_timeout_ms="$(prompt_default "security.request_timeout_ms" "500")"
    local cache_size
    cache_size="$(prompt_default "cache.max_size" "100000")"
    local cache_ttl_seconds
    cache_ttl_seconds="$(prompt_default "cache.ttl_seconds" "7200")"
    local metrics_listen
    metrics_listen="$(prompt_default "Prometheus listen address" "127.0.0.1:9100")"

    local cpu_cores
    cpu_cores="$(detect_cpu_cores)"
    local default_threads_udp=$((cpu_cores * 2))
    local default_threads_tcp=$((cpu_cores))
    if [ "$default_threads_udp" -lt 2 ]; then default_threads_udp=2; fi
    if [ "$default_threads_udp" -gt 64 ]; then default_threads_udp=64; fi
    if [ "$default_threads_tcp" -lt 1 ]; then default_threads_tcp=1; fi
    local threads_udp
    threads_udp="$(prompt_default "global.threads_udp" "${default_threads_udp}")"
    local threads_tcp
    threads_tcp="$(prompt_default "global.threads_tcp" "${default_threads_tcp}")"
    local max_tcp_clients
    max_tcp_clients="$(prompt_default "global.max_tcp_clients" "4096")"

    local upstream_mode
    upstream_mode="$(prompt_default "Upstream mode (udp|doh|mixed)" "mixed")"
    upstream_mode="$(printf '%s' "$upstream_mode" | tr '[:upper:]' '[:lower:]')"

    local udp_csv=""
    local doh_csv=""
    case "$upstream_mode" in
        udp)
            udp_csv="$(prompt_default "UDP upstreams CSV (ip:port@weight)" "1.1.1.1:53@5,8.8.8.8:53@5")"
            ;;
        doh)
            doh_csv="$(prompt_default "DoH upstreams CSV (url@weight)" "https://1.1.1.1/dns-query@5,https://8.8.8.8/dns-query@5")"
            ;;
        mixed)
            udp_csv="$(prompt_default "UDP upstreams CSV (ip:port@weight)" "1.1.1.1:53@5,8.8.8.8:53@5")"
            doh_csv="$(prompt_default "DoH upstreams CSV (url@weight)" "https://1.1.1.1/dns-query@5")"
            ;;
        *)
            printf 'Unsupported upstream mode: %s\n' "$upstream_mode" >&2
            exit 1
            ;;
    esac

    local plugins_csv
    plugins_csv="$(prompt_default "Plugin libraries CSV (.so/.dylib/.dll paths, optional)" "")"

    local hosts_remote_enabled
    hosts_remote_enabled="$(prompt_yes_no "Enable hosts_remote" "no")"
    local hosts_remote_url=""
    local hosts_remote_refresh="300"
    local hosts_remote_ttl="300"
    if [ "$hosts_remote_enabled" = "yes" ]; then
        hosts_remote_url="$(prompt_default "hosts_remote.url" "https://example.com/hosts.txt")"
        hosts_remote_refresh="$(prompt_default "hosts_remote.refresh_seconds" "300")"
        hosts_remote_ttl="$(prompt_default "hosts_remote.ttl_seconds" "300")"
    fi

    local blocklist_remote_enabled
    blocklist_remote_enabled="$(prompt_yes_no "Enable blocklist_remote" "no")"
    local blocklist_remote_url=""
    local blocklist_remote_refresh="600"
    if [ "$blocklist_remote_enabled" = "yes" ]; then
        blocklist_remote_url="$(prompt_default "blocklist_remote.url" "https://example.com/blocklist.txt")"
        blocklist_remote_refresh="$(prompt_default "blocklist_remote.refresh_seconds" "600")"
    fi

    local -a udp_items=()
    local -a doh_items=()
    local -a plugin_items=()
    while IFS= read -r item; do
        if [ -n "$item" ]; then
            udp_items+=("$item")
        fi
    done <<EOF
$(split_csv_trimmed "$udp_csv")
EOF
    while IFS= read -r item; do
        if [ -n "$item" ]; then
            doh_items+=("$item")
        fi
    done <<EOF
$(split_csv_trimmed "$doh_csv")
EOF
    while IFS= read -r item; do
        if [ -n "$item" ]; then
            plugin_items+=("$item")
        fi
    done <<EOF
$(split_csv_trimmed "$plugins_csv")
EOF

    if [ "${#udp_items[@]}" -eq 0 ] && [ "${#doh_items[@]}" -eq 0 ]; then
        printf 'At least one upstream is required\n' >&2
        exit 1
    fi

    local config_dir
    config_dir="$(dirname "$generated_config_path")"
    mkdir -p "$config_dir"
    local tmp_config
    tmp_config="$(mktemp "${config_dir}/balancedns.toml.XXXXXX")"

    {
        printf '[server]\n'
        printf 'udp_listen = "%s:%s"\n' "$listen_ip" "$udp_port"
        printf 'tcp_listen = "%s:%s"\n' "$listen_ip" "$tcp_port"
        if [ "$enable_dot" = "yes" ]; then
            printf 'dot_listen = "%s:%s"\n' "$listen_ip" "$dot_port"
        fi
        if [ "$enable_doh" = "yes" ]; then
            printf 'doh_listen = "%s:%s"\n' "$listen_ip" "$doh_port"
        fi

        if [ "$enable_dot" = "yes" ] || [ "$enable_doh" = "yes" ]; then
            printf '\n[tls]\n'
            printf 'cert_pem = "%s"\n' "$tls_cert_pem"
            printf 'key_pem = "%s"\n' "$tls_key_pem"
        fi

        printf '\n[balancing]\n'
        printf 'algorithm = "round_robin"\n'

        printf '\n[security]\n'
        printf 'deny_any = true\n'
        printf 'deny_dnskey = true\n'
        printf 'request_timeout_ms = %s\n' "$request_timeout_ms"

        printf '\n[cache]\n'
        printf 'enabled = true\n'
        printf 'max_size = %s\n' "$cache_size"
        printf 'ttl_seconds = %s\n' "$cache_ttl_seconds"
        printf 'min_ttl = 30\n'
        printf 'max_ttl = 86400\n'
        printf 'decrement_ttl = true\n'
        printf 'stale_refresh_enabled = true\n'
        printf 'stale_ttl_seconds = 30\n'

        printf '\n[metrics]\n'
        printf 'listen = "%s"\n' "$metrics_listen"

        printf '\n[hosts_local]\n'
        printf '# "example.local." = "192.168.1.100"\n'

        if [ "$hosts_remote_enabled" = "yes" ]; then
            printf '\n[hosts_remote]\n'
            printf 'url = "%s"\n' "$hosts_remote_url"
            printf 'refresh_seconds = %s\n' "$hosts_remote_refresh"
            printf 'ttl_seconds = %s\n' "$hosts_remote_ttl"
        fi

        if [ "$blocklist_remote_enabled" = "yes" ]; then
            printf '\n[blocklist_remote]\n'
            printf 'url = "%s"\n' "$blocklist_remote_url"
            printf 'refresh_seconds = %s\n' "$blocklist_remote_refresh"
        fi

        printf '\n[plugins]\n'
        if [ "${#plugin_items[@]}" -eq 0 ]; then
            printf 'libraries = []\n'
        else
            printf 'libraries = [%s]\n' "$(join_toml_string_array "${plugin_items[@]}")"
        fi

        printf '\n[global]\n'
        printf 'threads_udp = %s\n' "$threads_udp"
        printf 'threads_tcp = %s\n' "$threads_tcp"
        printf 'max_tcp_clients = %s\n' "$max_tcp_clients"
        printf 'max_waiting_clients = 1000000\n'
        printf 'max_active_queries = 200000\n'
        printf 'max_clients_waiting_for_query = 2000\n'
    } > "$tmp_config"

    local -a all_upstream_names=()
    local idx=0
    for item in "${udp_items[@]}"; do
        local parsed
        parsed="$(parse_endpoint_weight "$item" "5")"
        local endpoint="${parsed%%;*}"
        local weight="${parsed##*;}"
        if [ -z "$endpoint" ]; then
            continue
        fi
        idx=$((idx + 1))
        local name
        name="$(sanitize_name "udp-${idx}-${endpoint}")"
        append_upstream_block "$tmp_config" "$name" "udp" "$endpoint" "$weight"
        all_upstream_names+=("$name")
    done

    idx=0
    for item in "${doh_items[@]}"; do
        local parsed
        parsed="$(parse_endpoint_weight "$item" "5")"
        local endpoint="${parsed%%;*}"
        local weight="${parsed##*;}"
        if [ -z "$endpoint" ]; then
            continue
        fi
        idx=$((idx + 1))
        local name
        name="$(sanitize_name "doh-${idx}")"
        append_upstream_block "$tmp_config" "$name" "doh" "$endpoint" "$weight"
        all_upstream_names+=("$name")
    done

    {
        printf '\n[[routing_rules]]\n'
        printf 'suffix = "."\n'
        printf 'upstreams = [%s]\n' "$(join_toml_string_array "${all_upstream_names[@]}")"
    } >> "$tmp_config"

    mv -f "$tmp_config" "$generated_config_path"
    printf '\nConfig generated: %s\n' "$generated_config_path"

    local install_now
    install_now="$(prompt_yes_no "Install + deploy now via systemd" "yes")"
    if [ "$install_now" != "yes" ]; then
        printf 'Done. You can deploy later with scripts/install-systemd-safe.sh\n'
        exit 0
    fi

    local service_name
    service_name="$(prompt_default "Service name" "balancedns")"
    local service_user
    service_user="$(prompt_default "Service user" "balancedns")"
    local service_group
    service_group="$(prompt_default "Service group" "balancedns")"
    local binary_path
    binary_path="$(prompt_default "Server binary path" "/usr/sbin/balancedns")"
    local cli_binary_path
    cli_binary_path="$(prompt_default "Admin CLI binary path" "/usr/sbin/astracatdnscli")"
    local plugin_dir
    plugin_dir="$(prompt_default "Plugin install dir" "/usr/lib/balancedns/plugins")"
    local state_dir
    state_dir="$(prompt_default "State dir" "/var/lib/balancedns")"
    local config_path
    config_path="$(prompt_default "Final config path" "/etc/balancedns.toml")"
    local run_tests
    run_tests="$(prompt_yes_no "Run cargo tests during install" "no")"
    if [ "$run_tests" = "yes" ]; then
        run_tests="1"
    else
        run_tests="0"
    fi

    printf '\nStarting install...\n'
    if [ "$(id -u)" -eq 0 ]; then
        REPO_DIR="${REPO_DIR}" \
        SERVICE_NAME="${service_name}" \
        SERVICE_USER="${service_user}" \
        SERVICE_GROUP="${service_group}" \
        BINARY_PATH="${binary_path}" \
        CLI_BINARY_PATH="${cli_binary_path}" \
        PLUGIN_DIR="${plugin_dir}" \
        STATE_DIR="${state_dir}" \
        CONFIG_SOURCE="${generated_config_path}" \
        CONFIG_PATH="${config_path}" \
        OVERWRITE_CONFIG=1 \
        RUN_TESTS="${run_tests}" \
        "${REPO_DIR}/scripts/install-systemd-safe.sh"
    else
        sudo env \
            REPO_DIR="${REPO_DIR}" \
            SERVICE_NAME="${service_name}" \
            SERVICE_USER="${service_user}" \
            SERVICE_GROUP="${service_group}" \
            BINARY_PATH="${binary_path}" \
            CLI_BINARY_PATH="${cli_binary_path}" \
            PLUGIN_DIR="${plugin_dir}" \
            STATE_DIR="${state_dir}" \
            CONFIG_SOURCE="${generated_config_path}" \
            CONFIG_PATH="${config_path}" \
            OVERWRITE_CONFIG=1 \
            RUN_TESTS="${run_tests}" \
            "${REPO_DIR}/scripts/install-systemd-safe.sh"
    fi

    printf '\nInstall finished successfully.\n'
    printf 'Try: %s watch -c %s\n' "$cli_binary_path" "$config_path"
}

main "$@"
