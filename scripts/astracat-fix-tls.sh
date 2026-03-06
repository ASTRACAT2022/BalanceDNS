#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-astracat-dns}"
INSTALL_DIR="${INSTALL_DIR:-/opt/astracatdns}"
CONFIG_FILE="${CONFIG_FILE:-${INSTALL_DIR}/config.yaml}"
TARGET_DIR="${TARGET_CERT_DIR:-${INSTALL_DIR}/certs}"
TARGET_CERT="${TARGET_CERT_FILE:-${TARGET_DIR}/fullchain.pem}"
TARGET_KEY="${TARGET_KEY_FILE:-${TARGET_DIR}/privkey.pem}"

QUIET=0
NO_RESTART=0

log() {
  if [[ "${QUIET}" -eq 0 ]]; then
    printf '[TLSFIX] %s\n' "$*"
  fi
}

warn() {
  printf '[TLSFIX][WARN] %s\n' "$*" >&2
}

err() {
  printf '[TLSFIX][ERR] %s\n' "$*" >&2
}

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--quiet] [--no-restart]
  --quiet       Reduce output
  --no-restart  Only repair cert/key + config, skip systemctl restart
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quiet)
      QUIET=1
      shift
      ;;
    --no-restart)
      NO_RESTART=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      err "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  err "Run as root: sudo $(basename "$0")"
  exit 1
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
  err "Config not found: ${CONFIG_FILE}"
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  err "openssl is required"
  exit 1
fi

yaml_get_scalar() {
  local key="$1"
  awk -v k="${key}" '
    $0 ~ "^[[:space:]]*" k ":[[:space:]]*" {
      sub("^[[:space:]]*" k ":[[:space:]]*", "", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      gsub(/^"/, "", $0)
      gsub(/"$/, "", $0)
      print $0
      exit
    }
  ' "${CONFIG_FILE}"
}

yaml_set_string() {
  local key="$1"
  local value="$2"
  local escaped
  escaped="$(printf '%s' "${value}" | sed -e 's/[\/&|]/\\&/g')"
  if grep -Eq "^[[:space:]]*${key}:" "${CONFIG_FILE}"; then
    sed -i -E "s|^[[:space:]]*${key}:.*$|${key}: \"${escaped}\"|" "${CONFIG_FILE}"
  else
    printf '\n%s: "%s"\n' "${key}" "${value}" >> "${CONFIG_FILE}"
  fi
}

yaml_set_bool() {
  local key="$1"
  local value="$2"
  if grep -Eq "^[[:space:]]*${key}:" "${CONFIG_FILE}"; then
    sed -i -E "s|^[[:space:]]*${key}:.*$|${key}: ${value}|" "${CONFIG_FILE}"
  else
    printf '\n%s: %s\n' "${key}" "${value}" >> "${CONFIG_FILE}"
  fi
}

read_first_acme_domain() {
  awk '
    /^acme_domains:[[:space:]]*$/ { in_list=1; next }
    in_list && /^[[:space:]]*-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      gsub(/["'"'"'"]/, "", line)
      gsub(/[[:space:]]+$/, "", line)
      print line
      exit
    }
    in_list && /^[[:alnum:]_]+:/ { exit }
  ' "${CONFIG_FILE}"
}

resolve_path() {
  local p="$1"
  if [[ -z "${p}" ]]; then
    return 0
  fi
  if [[ "${p}" = /* ]]; then
    printf '%s\n' "${p}"
  else
    printf '%s\n' "${INSTALL_DIR}/${p}"
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

pair_matches() {
  local cert="$1"
  local key="$2"
  local cp="${tmp_dir}/cert.pub"
  local kp="${tmp_dir}/key.pub"

  [[ -f "${cert}" && -f "${key}" ]] || return 1
  openssl x509 -in "${cert}" -pubkey -noout > "${cp}" 2>/dev/null || return 1
  openssl pkey -in "${key}" -pubout > "${kp}" 2>/dev/null || return 1
  cmp -s "${cp}" "${kp}"
}

cert_has_domain() {
  local cert="$1"
  local domain="$2"
  [[ -n "${domain}" ]] || return 1
  openssl x509 -in "${cert}" -noout -text 2>/dev/null | grep -Eq "DNS:${domain}([[:space:],]|$)"
}

extract_port() {
  local addr="$1"
  if [[ "${addr}" =~ :([0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  fi
}

declare -a candidates=()
add_candidate() {
  local cert="$1"
  local key="$2"
  local pair="${cert}:::${key}"

  [[ -n "${cert}" && -n "${key}" ]] || return 0
  [[ -f "${cert}" && -f "${key}" ]] || return 0
  for existing in "${candidates[@]}"; do
    if [[ "${existing}" == "${pair}" ]]; then
      return 0
    fi
  done
  candidates+=("${pair}")
}

current_cert_raw="$(yaml_get_scalar cert_file || true)"
current_key_raw="$(yaml_get_scalar key_file || true)"
current_cert="$(resolve_path "${current_cert_raw}")"
current_key="$(resolve_path "${current_key_raw}")"
wanted_domain="$(read_first_acme_domain || true)"

add_candidate "${current_cert}" "${current_key}"
add_candidate "${TARGET_CERT}" "${TARGET_KEY}"

for d in /etc/letsencrypt/live/*; do
  [[ -d "${d}" ]] || continue
  add_candidate "${d}/fullchain.pem" "${d}/privkey.pem"
done

for cert in /etc/letsencrypt/archive/*/fullchain*.pem; do
  [[ -f "${cert}" ]] || continue
  add_candidate "${cert}" "${cert/fullchain/privkey}"
done

best_cert=""
best_key=""
best_score=-1

for entry in "${candidates[@]}"; do
  cert="${entry%%:::*}"
  key="${entry##*:::}"
  if ! pair_matches "${cert}" "${key}"; then
    continue
  fi

  score=0
  if [[ "${cert}" == "${current_cert}" && "${key}" == "${current_key}" ]]; then
    score=$((score + 20))
  fi
  if [[ "${cert}" == /etc/letsencrypt/live/* ]]; then
    score=$((score + 15))
  fi
  if cert_has_domain "${cert}" "${wanted_domain}"; then
    score=$((score + 100))
  fi

  if (( score > best_score )); then
    best_score="${score}"
    best_cert="${cert}"
    best_key="${key}"
  fi
done

mkdir -p "${TARGET_DIR}"
chmod 700 "${TARGET_DIR}" || true

if [[ -n "${best_cert}" && -n "${best_key}" ]]; then
  log "Using TLS pair: cert=${best_cert} key=${best_key}"
  install -m 0644 "${best_cert}" "${TARGET_CERT}"
  install -m 0600 "${best_key}" "${TARGET_KEY}"
else
  warn "No valid TLS pair found. Falling back to auto-generated self-signed cert."
  rm -f "${TARGET_CERT}" "${TARGET_KEY}"
fi

yaml_set_string cert_file "${TARGET_CERT}"
yaml_set_string key_file "${TARGET_KEY}"
yaml_set_bool acme_enabled false

if [[ "${NO_RESTART}" -eq 1 ]]; then
  log "TLS config repaired (no restart mode)."
  exit 0
fi

log "Restarting ${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"
sleep 2

dot_addr="$(yaml_get_scalar dot_addr || true)"
odoh_addr="$(yaml_get_scalar odoh_addr || true)"
dot_port="$(extract_port "${dot_addr}")"
odoh_port="$(extract_port "${odoh_addr}")"

journalctl -u "${SERVICE_NAME}" -n 80 --no-pager | grep -E "Failed to obtain TLS config|Starting DoT Server|Starting DoH/ODoH|disabled" || true
if [[ -n "${dot_port}" || -n "${odoh_port}" ]]; then
  pattern=""
  if [[ -n "${dot_port}" ]]; then
    pattern=":${dot_port} "
  fi
  if [[ -n "${odoh_port}" ]]; then
    if [[ -n "${pattern}" ]]; then
      pattern="${pattern}|:${odoh_port} "
    else
      pattern=":${odoh_port} "
    fi
  fi
  ss -ltnp | grep -E "${pattern}" || true
fi

log "TLS auto-fix complete."
