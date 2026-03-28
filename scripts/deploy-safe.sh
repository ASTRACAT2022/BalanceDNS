#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
REMOTE_NAME="${REMOTE_NAME:-origin}"
BRANCH="${BRANCH:-main}"
SERVICE_NAME="${SERVICE_NAME:-balancedns}"
BINARY_PATH="${BINARY_PATH:-/usr/sbin/balancedns}"
PLUGIN_DIR="${PLUGIN_DIR:-/usr/lib/balancedns/plugins}"
CONFIG_SOURCE="${CONFIG_SOURCE:-${REPO_DIR}/balancedns.toml}"
CONFIG_PATH="${CONFIG_PATH:-/etc/balancedns.toml}"
DEPLOY_CONFIG="${DEPLOY_CONFIG:-0}"
RUN_TESTS="${RUN_TESTS:-0}"
RESTART_SERVICE="${RESTART_SERVICE:-1}"

PREVIOUS_HEAD=""
ROLLBACK_DIR=""
DEPLOY_PHASE="prepare"
PLUGIN_NAMES=()
PLUGIN_MANIFESTS=()

log() {
    printf '[deploy] %s\n' "$*"
}

fail() {
    printf '[deploy] error: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "command not found: $1"
}

detect_lib_ext() {
    case "$(uname -s)" in
        Darwin) printf 'dylib' ;;
        Linux) printf 'so' ;;
        MINGW*|MSYS*|CYGWIN*) printf 'dll' ;;
        *) fail "unsupported platform: $(uname -s)" ;;
    esac
}

ensure_clean_repo() {
    if ! git diff --quiet || ! git diff --cached --quiet; then
        fail "repository has local changes; commit or stash them before deploy"
    fi
}

register_plugin() {
    local plugin_name="$1"
    local manifest_path="$2"
    if [ -f "${manifest_path}" ]; then
        PLUGIN_NAMES+=("${plugin_name}")
        PLUGIN_MANIFESTS+=("${manifest_path}")
    fi
}

rollback() {
    if [ "${DEPLOY_PHASE}" != "install" ] || [ -z "${ROLLBACK_DIR}" ] || [ ! -d "${ROLLBACK_DIR}" ]; then
        return
    fi
    log "rollback started"
    if [ -f "${ROLLBACK_DIR}/balancedns.previous" ]; then
        install -m 0755 "${ROLLBACK_DIR}/balancedns.previous" "${BINARY_PATH}"
    else
        rm -f "${BINARY_PATH}"
    fi
    mkdir -p "${PLUGIN_DIR}"
    for plugin_name in "${PLUGIN_NAMES[@]}"; do
        if [ -f "${ROLLBACK_DIR}/${plugin_name}.previous" ]; then
            install -m 0644 "${ROLLBACK_DIR}/${plugin_name}.previous" "${PLUGIN_DIR}/${plugin_name}.${LIB_EXT}"
        else
            rm -f "${PLUGIN_DIR}/${plugin_name}.${LIB_EXT}"
        fi
    done
    if [ "${DEPLOY_CONFIG}" = "1" ]; then
        if [ -f "${ROLLBACK_DIR}/balancedns.toml.previous" ]; then
            install -m 0644 "${ROLLBACK_DIR}/balancedns.toml.previous" "${CONFIG_PATH}"
        else
            rm -f "${CONFIG_PATH}"
        fi
    fi
    if [ -n "${PREVIOUS_HEAD}" ]; then
        git -C "${REPO_DIR}" reset --hard "${PREVIOUS_HEAD}" >/dev/null 2>&1 || true
    fi
    if [ "${RESTART_SERVICE}" = "1" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl restart "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
    log "rollback completed"
}

trap rollback ERR

require_cmd git
require_cmd cargo
require_cmd install

LIB_EXT="$(detect_lib_ext)"

[ -d "${REPO_DIR}" ] || fail "repo dir not found: ${REPO_DIR}"
[ -f "${REPO_DIR}/Cargo.toml" ] || fail "Cargo.toml not found in ${REPO_DIR}"

register_plugin "libbalancedns_remote_hosts_plugin" "${REPO_DIR}/plugins/remote-hosts-plugin/Cargo.toml"
register_plugin "libbalancedns_adblock_plugin" "${REPO_DIR}/plugins/adblock-plugin/Cargo.toml"

PREVIOUS_HEAD="$(git -C "${REPO_DIR}" rev-parse --verify HEAD 2>/dev/null || true)"

ensure_clean_repo

log "fetching ${REMOTE_NAME}/${BRANCH}"
git -C "${REPO_DIR}" fetch "${REMOTE_NAME}" "${BRANCH}"

if git -C "${REPO_DIR}" show-ref --verify --quiet "refs/heads/${BRANCH}"; then
    git -C "${REPO_DIR}" checkout "${BRANCH}"
else
    git -C "${REPO_DIR}" checkout -B "${BRANCH}" "${REMOTE_NAME}/${BRANCH}"
fi

git -C "${REPO_DIR}" reset --hard "${REMOTE_NAME}/${BRANCH}"

log "building release binary"
cargo build --release --manifest-path "${REPO_DIR}/Cargo.toml"

log "building plugins"
for manifest_path in "${PLUGIN_MANIFESTS[@]}"; do
    cargo build --release --manifest-path "${manifest_path}"
done

if [ "${RUN_TESTS}" = "1" ]; then
    log "running tests"
    cargo test --manifest-path "${REPO_DIR}/Cargo.toml"
fi

ROLLBACK_DIR="$(mktemp -d)"

if [ -f "${BINARY_PATH}" ]; then
    cp -p "${BINARY_PATH}" "${ROLLBACK_DIR}/balancedns.previous"
fi

mkdir -p "${PLUGIN_DIR}"
for plugin_name in "${PLUGIN_NAMES[@]}"; do
    if [ -f "${PLUGIN_DIR}/${plugin_name}.${LIB_EXT}" ]; then
        cp -p "${PLUGIN_DIR}/${plugin_name}.${LIB_EXT}" "${ROLLBACK_DIR}/${plugin_name}.previous"
    fi
done

if [ "${DEPLOY_CONFIG}" = "1" ] && [ -f "${CONFIG_PATH}" ]; then
    cp -p "${CONFIG_PATH}" "${ROLLBACK_DIR}/balancedns.toml.previous"
fi

DEPLOY_PHASE="install"

log "installing binary"
install -m 0755 "${REPO_DIR}/target/release/balancedns" "${BINARY_PATH}.new"
mv -f "${BINARY_PATH}.new" "${BINARY_PATH}"

log "installing plugins"
for plugin_name in "${PLUGIN_NAMES[@]}"; do
    plugin_output="$(find "${REPO_DIR}/plugins" -path "*/target/release/${plugin_name}.${LIB_EXT}" -print -quit)"
    [ -n "${plugin_output}" ] || fail "built plugin not found: ${plugin_name}.${LIB_EXT}"
    install -m 0644 "${plugin_output}" "${PLUGIN_DIR}/${plugin_name}.${LIB_EXT}.new"
    mv -f "${PLUGIN_DIR}/${plugin_name}.${LIB_EXT}.new" "${PLUGIN_DIR}/${plugin_name}.${LIB_EXT}"
done

if [ "${DEPLOY_CONFIG}" = "1" ]; then
    [ -f "${CONFIG_SOURCE}" ] || fail "config source not found: ${CONFIG_SOURCE}"
    log "installing config"
    install -m 0644 "${CONFIG_SOURCE}" "${CONFIG_PATH}.new"
    mv -f "${CONFIG_PATH}.new" "${CONFIG_PATH}"
fi

if [ "${RESTART_SERVICE}" = "1" ]; then
    require_cmd systemctl
    log "restarting service ${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"
    systemctl is-active --quiet "${SERVICE_NAME}"
fi

DEPLOY_PHASE="done"

rm -rf "${ROLLBACK_DIR}"

log "deploy completed successfully"
