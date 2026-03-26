#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found" >&2
  exit 1
fi

cd "${ROOT_DIR}"

cargo build --release --bin astracat-dns

install -d /usr/local/bin
install -m 0755 "${ROOT_DIR}/target/release/astracat-dns" /usr/local/bin/astracat-dns

if ! id -u astracat-dns >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin astracat-dns
  elif command -v adduser >/dev/null 2>&1; then
    adduser --system --no-create-home --disabled-login --shell /usr/sbin/nologin astracat-dns
  else
    echo "no useradd/adduser" >&2
    exit 1
  fi
fi

install -d -m 0755 /etc/astracat-dns
if [[ ! -f /etc/astracat-dns/config.toml ]]; then
  install -m 0644 "${ROOT_DIR}/config/astracat-dns.toml" /etc/astracat-dns/config.toml
fi

install -d -m 0755 /etc/astracat-dns/tls
if [[ ! -f /etc/astracat-dns/tls/server.crt || ! -f /etc/astracat-dns/tls/server.key ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /etc/astracat-dns/tls/server.key \
      -out /etc/astracat-dns/tls/server.crt \
      -days 3650 \
      -subj "/CN=astracat-dns" >/dev/null 2>&1
    chmod 0644 /etc/astracat-dns/tls/server.crt
    chmod 0600 /etc/astracat-dns/tls/server.key
    chown -R astracat-dns:astracat-dns /etc/astracat-dns/tls
  else
    echo "openssl not found; place TLS cert/key into /etc/astracat-dns/tls" >&2
    exit 1
  fi
fi

install -m 0644 "${ROOT_DIR}/packaging/astracat-dns.service" /etc/systemd/system/astracat-dns.service

systemctl daemon-reload
systemctl enable --now astracat-dns
systemctl status --no-pager astracat-dns || true
