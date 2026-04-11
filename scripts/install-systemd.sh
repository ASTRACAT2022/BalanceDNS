#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-balancedns}"
PREFIX="${PREFIX:-/usr/local}"
BIN_PATH="${PREFIX}/bin/balancedns"
ETC_DIR="${ETC_DIR:-/etc/balancedns}"
CONFIG_SRC="${CONFIG_SRC:-configs/balancedns.lua}"
CONFIG_DST="${ETC_DIR}/balancedns.lua"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
RUN_USER="${RUN_USER:-balancedns}"
RUN_GROUP="${RUN_GROUP:-balancedns}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer supports Linux/systemd only." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found. Install systemd or deploy manually." >&2
  exit 1
fi

SUDO=""
if [[ "${EUID}" -ne 0 ]]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "Run as root or install sudo." >&2
    exit 1
  fi
  SUDO="sudo"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

TMP_BIN="$(mktemp /tmp/balancedns-build-XXXXXX)"
trap 'rm -f "${TMP_BIN}"' EXIT

echo "[1/6] Building BalanceDNS binary"
go build -o "${TMP_BIN}" ./cmd/balancedns

echo "[2/6] Creating service user/group (if missing)"
if ! getent group "${RUN_GROUP}" >/dev/null 2>&1; then
  ${SUDO} groupadd --system "${RUN_GROUP}"
fi
if ! id -u "${RUN_USER}" >/dev/null 2>&1; then
  ${SUDO} useradd --system --no-create-home --gid "${RUN_GROUP}" --shell /usr/sbin/nologin "${RUN_USER}"
fi

echo "[3/6] Installing binary and configuration"
${SUDO} install -d -m 0755 "$(dirname "${BIN_PATH}")"
${SUDO} install -m 0755 "${TMP_BIN}" "${BIN_PATH}"
${SUDO} install -d -m 0750 "${ETC_DIR}"
if [[ ! -f "${CONFIG_DST}" ]]; then
  ${SUDO} install -m 0640 "${CONFIG_SRC}" "${CONFIG_DST}"
  echo "Config installed to ${CONFIG_DST}"
else
  echo "Config already exists at ${CONFIG_DST}; not overwriting"
fi
${SUDO} chown root:"${RUN_GROUP}" "${CONFIG_DST}"
${SUDO} chmod 0640 "${CONFIG_DST}"

echo "[4/6] Writing systemd service ${SERVICE_PATH}"
${SUDO} tee "${SERVICE_PATH}" >/dev/null <<UNIT
[Unit]
Description=BalanceDNS resolver/forwarder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
ExecStart=${BIN_PATH} -config ${CONFIG_DST}
Restart=always
RestartSec=2
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
UNIT

echo "[5/6] Reloading systemd and enabling service"
${SUDO} systemctl daemon-reload
${SUDO} systemctl enable --now "${SERVICE_NAME}"

echo "[6/6] Service status"
${SUDO} systemctl --no-pager --full status "${SERVICE_NAME}" || true

echo "Installation completed."
