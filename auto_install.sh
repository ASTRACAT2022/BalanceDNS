#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="astracat-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="/opt/astracatdns"
BINARY_NAME="dns-resolver"
ROOT_ANCHOR="/var/lib/unbound/root.key"
DEPLOY_HELPER="/usr/local/bin/astracat-deploy"
TLS_FIX_HELPER="/usr/local/bin/astracat-fix-tls"
STATE_DIR="/etc/astracatdns"
SOURCE_FILE="${STATE_DIR}/source_dir"
GO_BIN=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERR ] %s\n' "$*" >&2; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Run as root: sudo ./auto_install.sh"
    exit 1
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

version_ge() {
  # returns 0 when $1 >= $2
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

install_deps() {
  if command_exists apt-get; then
    export DEBIAN_FRONTEND=noninteractive
    log "Installing dependencies via apt..."
    apt-get update
    apt-get install -y \
      ca-certificates \
      curl \
      wget \
      openssl \
      tar \
      rsync \
      build-essential \
      pkg-config \
      libunbound-dev \
      unbound-anchor \
      dns-root-data
    return
  fi

  if command_exists dnf; then
    log "Installing dependencies via dnf..."
    dnf install -y \
      ca-certificates \
      curl \
      wget \
      openssl \
      tar \
      rsync \
      gcc \
      gcc-c++ \
      make \
      pkgconf-pkg-config \
      unbound-devel \
      unbound
    return
  fi

  warn "No supported package manager (apt/dnf). Install build deps manually."
}

ensure_go() {
  local req_go cur_go arch os go_tgz go_url
  req_go="$(awk '/^go / {print $2; exit}' "${PROJECT_DIR}/go.mod")"
  req_go="${req_go:-1.24.0}"

  if command_exists go; then
    GO_BIN="$(command -v go)"
    cur_go="$(go version | awk '{print $3}' | sed 's/^go//')"
    if version_ge "${cur_go}" "${req_go}"; then
      log "Go ${cur_go} already satisfies required ${req_go}"
      return
    fi
    warn "Go ${cur_go} is older than required ${req_go}; updating."
  else
    log "Go not found; installing ${req_go}"
  fi

  os="linux"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      err "Unsupported architecture: ${arch}"
      exit 1
      ;;
  esac

  go_tgz="go${req_go}.${os}-${arch}.tar.gz"
  go_url="https://go.dev/dl/${go_tgz}"

  log "Downloading ${go_url}"
  if command_exists curl; then
    curl -fsSL "${go_url}" -o "/tmp/${go_tgz}"
  elif command_exists wget; then
    wget -qO "/tmp/${go_tgz}" "${go_url}"
  else
    err "curl/wget not found, cannot download Go"
    exit 1
  fi

  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${go_tgz}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  rm -f "/tmp/${go_tgz}"
  GO_BIN="/usr/local/go/bin/go"

  log "Installed Go: $(/usr/local/go/bin/go version)"
}

prepare_install_dir() {
  log "Preparing ${INSTALL_DIR}"
  mkdir -p "${INSTALL_DIR}"

  if command_exists rsync; then
    rsync -a \
      --exclude '.git' \
      --exclude '.github' \
      --exclude '.DS_Store' \
      --exclude "${BINARY_NAME}" \
      "${PROJECT_DIR}/" "${INSTALL_DIR}/"
  else
    cp -a "${PROJECT_DIR}/." "${INSTALL_DIR}/"
    rm -rf "${INSTALL_DIR}/.git" "${INSTALL_DIR}/.github"
  fi
}

write_runtime_state() {
  mkdir -p "${STATE_DIR}"
  printf '%s\n' "${PROJECT_DIR}" > "${SOURCE_FILE}"
  chmod 0644 "${SOURCE_FILE}" || true
}

build_binary() {
  log "Building project"
  cd "${INSTALL_DIR}"
  if [[ -z "${GO_BIN}" ]]; then
    GO_BIN="$(command -v go || true)"
  fi
  if [[ -z "${GO_BIN}" ]]; then
    err "go binary not found after installation step"
    exit 1
  fi
  CGO_ENABLED=1 "${GO_BIN}" build -o "${BINARY_NAME}" .
  if [[ ! -x "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
    err "Build failed: ${INSTALL_DIR}/${BINARY_NAME} not found"
    exit 1
  fi
}

ensure_root_anchor() {
  mkdir -p "$(dirname "${ROOT_ANCHOR}")"
  if command_exists unbound-anchor; then
    log "Refreshing DNSSEC root anchor via unbound-anchor"
    unbound-anchor -a "${ROOT_ANCHOR}" || warn "unbound-anchor failed, continuing"
  elif [[ ! -f "${ROOT_ANCHOR}" ]]; then
    warn "unbound-anchor is missing and root key is absent: ${ROOT_ANCHOR}"
  fi
  chmod 0644 "${ROOT_ANCHOR}" 2>/dev/null || true
}

write_service() {
  log "Creating systemd unit ${SERVICE_FILE}"
  cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=ASTRACAT DNS Resolver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/${BINARY_NAME}
Restart=always
RestartSec=3
LimitNOFILE=262144
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

install_deploy_helper() {
  log "Installing deploy helper at ${DEPLOY_HELPER}"
  cat > "${DEPLOY_HELPER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME}"
INSTALL_DIR="${INSTALL_DIR}"
BINARY_NAME="${BINARY_NAME}"
SOURCE_FILE="${SOURCE_FILE}"

log() { printf '[DEPLOY] %s\n' "\$*"; }
err() { printf '[DEPLOY][ERR] %s\n' "\$*" >&2; }

if [[ "\${EUID}" -ne 0 ]]; then
  err "Run as root: sudo astracat-deploy"
  exit 1
fi

if [[ -d "\${INSTALL_DIR}/.git" ]]; then
  log "Git repository detected in \${INSTALL_DIR}, pulling main..."
  git -C "\${INSTALL_DIR}" fetch origin
  git -C "\${INSTALL_DIR}" checkout main
  git -C "\${INSTALL_DIR}" pull --ff-only origin main
else
  SRC_DIR=""
  if [[ -f "\${SOURCE_FILE}" ]]; then
    SRC_DIR="\$(tr -d '\n' < "\${SOURCE_FILE}")"
  fi
  if [[ -z "\${SRC_DIR}" || ! -d "\${SRC_DIR}" ]]; then
    err "Source directory is not configured or missing. Expected in \${SOURCE_FILE}."
    exit 1
  fi
  if [[ "\${SRC_DIR}" == "\${INSTALL_DIR}" ]]; then
    log "Source and install directories are identical, skipping sync step."
  else
    log "Syncing source from \${SRC_DIR} -> \${INSTALL_DIR}"
    if command -v rsync >/dev/null 2>&1; then
      rsync -a --delete --exclude '.git' --exclude '.github' --exclude '.DS_Store' "\${SRC_DIR}/" "\${INSTALL_DIR}/"
    else
      cp -a "\${SRC_DIR}/." "\${INSTALL_DIR}/"
      rm -rf "\${INSTALL_DIR}/.git" "\${INSTALL_DIR}/.github"
    fi
  fi
fi

GO_BIN="\$(command -v go || true)"
if [[ -z "\${GO_BIN}" && -x /usr/local/go/bin/go ]]; then
  GO_BIN="/usr/local/go/bin/go"
fi
if [[ -z "\${GO_BIN}" ]]; then
  err "go compiler is not installed"
  exit 1
fi

log "Building \${BINARY_NAME} in \${INSTALL_DIR}"
cd "\${INSTALL_DIR}"
"\${GO_BIN}" clean -cache
CGO_ENABLED=1 "\${GO_BIN}" build -a -o "\${INSTALL_DIR}/\${BINARY_NAME}" .

if command -v astracat-fix-tls >/dev/null 2>&1; then
  log "Repairing TLS cert/key config automatically"
  astracat-fix-tls --no-restart --quiet || log "TLS auto-fix skipped (continuing deployment)"
fi

log "Restarting \${SERVICE_NAME}"
systemctl restart "\${SERVICE_NAME}"
systemctl --no-pager --full status "\${SERVICE_NAME}" || true
journalctl -u "\${SERVICE_NAME}" -n 20 --no-pager || true
EOF
  chmod 0755 "${DEPLOY_HELPER}"
}

install_tls_fix_helper() {
  local src="${INSTALL_DIR}/scripts/astracat-fix-tls.sh"
  if [[ ! -f "${src}" ]]; then
    src="${PROJECT_DIR}/scripts/astracat-fix-tls.sh"
  fi
  if [[ ! -f "${src}" ]]; then
    warn "TLS helper script not found, skipping: ${src}"
    return
  fi

  log "Installing TLS auto-fix helper at ${TLS_FIX_HELPER}"
  install -m 0755 "${src}" "${TLS_FIX_HELPER}"
}

start_service() {
  log "Reloading systemd and starting ${SERVICE_NAME}"
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" --now
  sleep 2
  systemctl --no-pager --full status "${SERVICE_NAME}" || true
}

main() {
  require_root
  log "Starting ASTRACAT DNS auto-install"
  install_deps
  ensure_go
  prepare_install_dir
  write_runtime_state
  build_binary
  ensure_root_anchor
  write_service
  install_tls_fix_helper
  install_deploy_helper
  start_service
  log "Done. Service '${SERVICE_NAME}' is installed."
  log "Use 'sudo astracat-deploy' for safe updates and restarts."
  log "Use 'sudo astracat-fix-tls' to auto-repair TLS cert/key and restart."
}

main "$@"
