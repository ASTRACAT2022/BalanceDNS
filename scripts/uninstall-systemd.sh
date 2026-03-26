#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

systemctl disable --now astracat-dns || true
rm -f /etc/systemd/system/astracat-dns.service
systemctl daemon-reload

rm -f /usr/local/bin/astracat-dns

echo "left config in /etc/astracat-dns" >&2

