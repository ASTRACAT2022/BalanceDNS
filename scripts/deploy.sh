#!/usr/bin/env bash
set -euo pipefail

# 1. Root check
if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: This script must be run as root. Use: sudo $0" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="/usr/local/bin/astracat-dns"
BACKUP_PATH="/usr/local/bin/astracat-dns.bak"
SERVICE_NAME="astracat-dns"

echo "=== Starting deployment for ${SERVICE_NAME} ==="

# Check if cargo is available
if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Please install Rust." >&2
  exit 1
fi

# 2. Build
echo "Building project..."
cd "${ROOT_DIR}"
# Try to build as the original user if running under sudo to avoid root-owned artifacts
BUILD_CMD="cargo build --release --bin astracat-dns"
if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  echo "Building as user ${SUDO_USER}..."
  if ! sudo -u "${SUDO_USER}" $BUILD_CMD; then
    echo "Error: Build failed!" >&2
    exit 1
  fi
else
  if ! $BUILD_CMD; then
    echo "Error: Build failed!" >&2
    exit 1
  fi
fi

# 3. Backup existing binary
HAS_BACKUP=false
if [[ -f "${BIN_PATH}" ]]; then
  echo "Backing up existing binary to ${BACKUP_PATH}..."
  # Use cp to keep a copy, but install later will handle the replacement safely
  cp "${BIN_PATH}" "${BACKUP_PATH}"
  HAS_BACKUP=true
fi

# 4. Install new binary
echo "Installing new binary..."
# Ensure directory exists
mkdir -p "$(dirname "${BIN_PATH}")"
# Use install to avoid "Text file busy" error if the binary is currently in use
install -m 0755 "${ROOT_DIR}/target/release/astracat-dns" "${BIN_PATH}"

# 5. Restart or Start service
echo "Managing service ${SERVICE_NAME}..."

# If service file doesn't exist, we run the install script
if ! systemctl list-unit-files | grep -q "${SERVICE_NAME}.service"; then
  echo "Service ${SERVICE_NAME} not found. Running install-systemd.sh..."
  if [[ -f "${ROOT_DIR}/scripts/install-systemd.sh" ]]; then
     bash "${ROOT_DIR}/scripts/install-systemd.sh"
  else
     echo "Error: scripts/install-systemd.sh not found. Cannot install service." >&2
     exit 1
  fi
else
  echo "Restarting service..."
  if ! systemctl restart "${SERVICE_NAME}"; then
    echo "Error: Failed to restart service!" >&2
    # Rollback immediately if restart fails
    if [[ "${HAS_BACKUP}" == "true" ]]; then
      echo "Rolling back to backup binary..."
      install -m 0755 "${BACKUP_PATH}" "${BIN_PATH}"
      systemctl restart "${SERVICE_NAME}"
    fi
    exit 1
  fi
fi

# 6. Health check
echo "Waiting for service to stabilize..."
sleep 3

if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
  echo "Error: Service is not active after deployment!" >&2
  # 7. Rollback
  if [[ "${HAS_BACKUP}" == "true" ]]; then
    echo "Rolling back to backup binary..."
    install -m 0755 "${BACKUP_PATH}" "${BIN_PATH}"
    systemctl restart "${SERVICE_NAME}"
    echo "Rollback complete. Previous version restored."
  else
    echo "No backup found to rollback to."
  fi
  exit 1
fi

echo "=== Deployment successful! ==="
if [[ "${HAS_BACKUP}" == "true" ]]; then
  rm -f "${BACKUP_PATH}"
fi
