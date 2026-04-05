#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
SERVICE_NAME="${SERVICE_NAME:-balancedns}"
SERVICE_USER="${SERVICE_USER:-balancedns}"
SERVICE_GROUP="${SERVICE_GROUP:-balancedns}"
SYSTEMD_UNIT_PATH="${SYSTEMD_UNIT_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
BINARY_PATH="${BINARY_PATH:-/usr/sbin/balancedns}"
CLI_BINARY_PATH="${CLI_BINARY_PATH:-/usr/sbin/astracatdnscli}"
PLUGIN_DIR="${PLUGIN_DIR:-/usr/lib/balancedns/plugins}"
CONFIG_SOURCE="${CONFIG_SOURCE:-${REPO_DIR}/balancedns.toml}"
CONFIG_PATH="${CONFIG_PATH:-/etc/balancedns.toml}"
STATE_DIR="${STATE_DIR:-/var/lib/balancedns}"
OVERWRITE_CONFIG="${OVERWRITE_CONFIG:-0}"
RUN_TESTS="${RUN_TESTS:-0}"

log() {
    printf '[install] %s\n' "$*"
}

fail() {
    printf '[install] error: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "command not found: $1"
}

ensure_root() {
    [ "$(id -u)" -eq 0 ] || fail "run as root"
}

ensure_group() {
    if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
        groupadd --system "${SERVICE_GROUP}"
    fi
}

ensure_user() {
    if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
        useradd \
            --system \
            --gid "${SERVICE_GROUP}" \
            --home-dir "${STATE_DIR}" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "${SERVICE_USER}"
    fi
}

install_config() {
    if [ ! -f "${CONFIG_SOURCE}" ]; then
        fail "config source not found: ${CONFIG_SOURCE}"
    fi
    if [ -f "${CONFIG_PATH}" ] && [ "${OVERWRITE_CONFIG}" != "1" ]; then
        log "keeping existing config at ${CONFIG_PATH}"
        return
    fi
    install -m 0640 -o root -g "${SERVICE_GROUP}" "${CONFIG_SOURCE}" "${CONFIG_PATH}.new"
    mv -f "${CONFIG_PATH}.new" "${CONFIG_PATH}"
}

install_unit() {
    awk \
        -v service_user="${SERVICE_USER}" \
        -v service_group="${SERVICE_GROUP}" \
        -v binary_path="${BINARY_PATH}" \
        -v config_path="${CONFIG_PATH}" \
        '
        /^User=/ { print "User=" service_user; next }
        /^Group=/ { print "Group=" service_group; next }
        /^ReadOnlyPaths=/ { print "ReadOnlyPaths=" config_path; next }
        /^ExecStart=/ { print "ExecStart=" binary_path " --config " config_path; next }
        { print }
        ' "${REPO_DIR}/balancedns.service" > "${SYSTEMD_UNIT_PATH}.new"
    chmod 0644 "${SYSTEMD_UNIT_PATH}.new"
    mv -f "${SYSTEMD_UNIT_PATH}.new" "${SYSTEMD_UNIT_PATH}"
}

prepare_dirs() {
    install -d -m 0755 /usr/lib/balancedns
    install -d -m 0755 "${PLUGIN_DIR}"
    install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${STATE_DIR}"
}

main() {
    ensure_root
    require_cmd git
    require_cmd cargo
    require_cmd install
    require_cmd systemctl

    [ -d "${REPO_DIR}" ] || fail "repo dir not found: ${REPO_DIR}"
    [ -f "${REPO_DIR}/balancedns.service" ] || fail "service template not found"
    [ -f "${REPO_DIR}/scripts/deploy-safe.sh" ] || fail "deploy-safe.sh not found"

    ensure_group
    ensure_user
    prepare_dirs
    install_config
    install_unit

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"

    RESTART_SERVICE=0 \
    DEPLOY_CONFIG=0 \
    RUN_TESTS="${RUN_TESTS}" \
    SERVICE_NAME="${SERVICE_NAME}" \
    BINARY_PATH="${BINARY_PATH}" \
    CLI_BINARY_PATH="${CLI_BINARY_PATH}" \
    PLUGIN_DIR="${PLUGIN_DIR}" \
    CONFIG_PATH="${CONFIG_PATH}" \
    REPO_DIR="${REPO_DIR}" \
    "${REPO_DIR}/scripts/deploy-safe.sh"

    systemctl restart "${SERVICE_NAME}"
    systemctl is-active --quiet "${SERVICE_NAME}"

    log "systemd unit installed: ${SYSTEMD_UNIT_PATH}"
    log "binary installed: ${BINARY_PATH}"
    log "admin cli installed: ${CLI_BINARY_PATH}"
    log "plugins installed: ${PLUGIN_DIR}"
    log "config path: ${CONFIG_PATH}"
    log "service is active"
}

main "$@"
