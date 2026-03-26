#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/config/tls"

mkdir -p "${OUT_DIR}"

if [[ -f "${OUT_DIR}/server.crt" && -f "${OUT_DIR}/server.key" ]]; then
  echo "${OUT_DIR}/server.crt and server.key already exist" >&2
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found" >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${OUT_DIR}/server.key" \
  -out "${OUT_DIR}/server.crt" \
  -days 3650 \
  -subj "/CN=astracat-dns" >/dev/null 2>&1

chmod 0644 "${OUT_DIR}/server.crt"
chmod 0600 "${OUT_DIR}/server.key"

echo "generated ${OUT_DIR}/server.crt and ${OUT_DIR}/server.key" >&2

