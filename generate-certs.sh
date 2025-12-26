#!/bin/bash
set -e

CERT_DIR="/etc/astracat-dns/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.key" ] && [ -f "$CERT_DIR/server.crt" ]; then
    echo "Certificates already exist in $CERT_DIR"
    exit 0
fi

echo "Generating self-signed certificates for Astracat DNS..."
openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" -days 365 -nodes -subj "/CN=dns.astracat.ru"

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"
chown -R $(whoami) "$CERT_DIR"

echo "Certificates generated successfully at $CERT_DIR"
