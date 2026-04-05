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
            *) printf 'Введите yes/y или no/n\n' ;;
        esac
    done
}

prompt_required_csv() {
    local prompt="$1"
    local default="$2"
    local value=""
    while true; do
        value="$(prompt_default "$prompt" "$default")"
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return 0
        fi
        printf 'Список не должен быть пустым\n'
    done
}

split_csv_trimmed() {
    local source="$1"
    local -a raw_items=()
    IFS=',' read -r -a raw_items <<< "$source"
    for raw_item in "${raw_items[@]}"; do
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

main() {
    local default_config_path="${REPO_DIR}/balancedns.toml"
    local config_path
    config_path="$(prompt_default "Куда сохранить конфиг" "$default_config_path")"

    local listen_ip
    listen_ip="$(prompt_default "IP для listeners" "0.0.0.0")"
    local udp_port
    udp_port="$(prompt_default "Порт UDP listener" "53")"
    local tcp_port
    tcp_port="$(prompt_default "Порт TCP listener" "53")"

    local enable_dot
    enable_dot="$(prompt_yes_no "Включить DoT listener" "yes")"
    local dot_port="853"
    if [ "$enable_dot" = "yes" ]; then
        dot_port="$(prompt_default "Порт DoT listener" "853")"
    fi

    local enable_doh
    enable_doh="$(prompt_yes_no "Включить DoH listener" "yes")"
    local doh_port="443"
    if [ "$enable_doh" = "yes" ]; then
        doh_port="$(prompt_default "Порт DoH listener" "443")"
    fi

    local tls_cert_pem="/var/lib/balancedns/tls/server.crt"
    local tls_key_pem="/var/lib/balancedns/tls/server.key"
    if [ "$enable_dot" = "yes" ] || [ "$enable_doh" = "yes" ]; then
        tls_cert_pem="$(prompt_default "Путь к TLS cert_pem" "$tls_cert_pem")"
        tls_key_pem="$(prompt_default "Путь к TLS key_pem" "$tls_key_pem")"
    fi

    local upstream_mode
    upstream_mode="$(prompt_default "Режим upstream (udp|doh|mixed)" "mixed")"
    upstream_mode="$(printf '%s' "$upstream_mode" | tr '[:upper:]' '[:lower:]')"

    local udp_csv=""
    local doh_csv=""
    case "$upstream_mode" in
        udp)
            udp_csv="$(prompt_required_csv "UDP upstreams через запятую (ip:port)" "1.1.1.1:53,8.8.8.8:53")"
            ;;
        doh)
            doh_csv="$(prompt_required_csv "DoH upstreams через запятую (url)" "https://1.1.1.1/dns-query,https://8.8.8.8/dns-query")"
            ;;
        mixed)
            udp_csv="$(prompt_required_csv "UDP upstreams через запятую (ip:port)" "1.1.1.1:53,8.8.8.8:53")"
            doh_csv="$(prompt_required_csv "DoH upstreams через запятую (url)" "https://1.1.1.1/dns-query")"
            ;;
        *)
            printf 'Неверный режим upstream: %s\n' "$upstream_mode" >&2
            exit 1
            ;;
    esac

    local request_timeout_ms
    request_timeout_ms="$(prompt_default "request_timeout_ms" "500")"
    local cache_size
    cache_size="$(prompt_default "cache.max_size" "100000")"
    local cache_ttl_seconds
    cache_ttl_seconds="$(prompt_default "cache.ttl_seconds" "3600")"
    local metrics_listen
    metrics_listen="$(prompt_default "Prometheus listen addr" "127.0.0.1:9100")"

    local cpu_cores
    cpu_cores="$(detect_cpu_cores)"
    local default_threads_udp=$((cpu_cores * 2))
    local default_threads_tcp=$((cpu_cores))
    if [ "$default_threads_udp" -lt 2 ]; then
        default_threads_udp=2
    fi
    if [ "$default_threads_udp" -gt 64 ]; then
        default_threads_udp=64
    fi
    if [ "$default_threads_tcp" -lt 1 ]; then
        default_threads_tcp=1
    fi
    local threads_udp
    threads_udp="$(prompt_default "global.threads_udp" "${default_threads_udp}")"
    local threads_tcp
    threads_tcp="$(prompt_default "global.threads_tcp" "${default_threads_tcp}")"
    local max_tcp_clients
    max_tcp_clients="$(prompt_default "global.max_tcp_clients" "4096")"

    local -a udp_upstreams=()
    local -a doh_upstreams=()
    while IFS= read -r item; do
        if [ -n "$item" ]; then
            udp_upstreams+=("$item")
        fi
    done <<EOF
$(split_csv_trimmed "$udp_csv")
EOF
    while IFS= read -r item; do
        if [ -n "$item" ]; then
            doh_upstreams+=("$item")
        fi
    done <<EOF
$(split_csv_trimmed "$doh_csv")
EOF

    if [ "${#udp_upstreams[@]}" -eq 0 ] && [ "${#doh_upstreams[@]}" -eq 0 ]; then
        printf 'Нужен хотя бы один upstream\n' >&2
        exit 1
    fi

    local config_dir
    config_dir="$(dirname "$config_path")"
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

        printf '\n[plugins]\n'
        printf 'libraries = []\n'

        printf '\n[global]\n'
        printf 'threads_udp = %s\n' "$threads_udp"
        printf 'threads_tcp = %s\n' "$threads_tcp"
        printf 'max_tcp_clients = %s\n' "$max_tcp_clients"
        printf 'max_waiting_clients = 1000000\n'
        printf 'max_active_queries = 200000\n'
        printf 'max_clients_waiting_for_query = 2000\n'
    } > "$tmp_config"

    local -a all_upstream_names=()
    local i=0
    for i in "${!udp_upstreams[@]}"; do
        local name="upstream-udp-$((i + 1))"
        append_upstream_block "$tmp_config" "$name" "udp" "${udp_upstreams[$i]}" "5"
        all_upstream_names+=("$name")
    done

    for i in "${!doh_upstreams[@]}"; do
        local name="upstream-doh-$((i + 1))"
        append_upstream_block "$tmp_config" "$name" "doh" "${doh_upstreams[$i]}" "5"
        all_upstream_names+=("$name")
    done

    {
        printf '\n[[routing_rules]]\n'
        printf 'suffix = "."\n'
        printf 'upstreams = [%s]\n' "$(join_toml_string_array "${all_upstream_names[@]}")"
    } >> "$tmp_config"

    mv -f "$tmp_config" "$config_path"
    printf '\nГотово: конфиг сохранен в %s\n' "$config_path"
    printf 'Prometheus endpoint: http://%s/metrics\n' "$metrics_listen"

    local run_build
    run_build="$(prompt_yes_no "Собрать release бинарник сейчас" "yes")"
    if [ "$run_build" = "yes" ]; then
        cargo build --release --manifest-path "${REPO_DIR}/Cargo.toml"
        printf 'Release binary: %s\n' "${REPO_DIR}/target/release/balancedns"
    fi

    local run_install
    run_install="$(prompt_yes_no "Запустить install-systemd-safe.sh (нужен root)" "no")"
    if [ "$run_install" = "yes" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            REPO_DIR="${REPO_DIR}" \
            CONFIG_SOURCE="${config_path}" \
            OVERWRITE_CONFIG=1 \
            "${REPO_DIR}/scripts/install-systemd-safe.sh"
        else
            sudo env \
                REPO_DIR="${REPO_DIR}" \
                CONFIG_SOURCE="${config_path}" \
                OVERWRITE_CONFIG=1 \
                "${REPO_DIR}/scripts/install-systemd-safe.sh"
        fi
    fi
}

main "$@"
