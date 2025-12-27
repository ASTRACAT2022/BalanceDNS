#!/bin/bash
set -e

CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/server.key" ] && [ -f "$CERT_DIR/server.crt" ]; then
    echo "Certificates already exist in $CERT_DIR"
    exit 0
fi

echo "Generating self-signed certificates for Astracat DNS with IP SANs..."

# Create a config file for OpenSSL
cat > "$CERT_DIR/openssl.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = dns.astracat.ru

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = dns.astracat.ru
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" -days 365 -nodes -config "$CERT_DIR/openssl.cnf"

chmod 600 "$CERT_DIR/server.key"
chmod 644 "$CERT_DIR/server.crt"
# chown -R $(whoami) "$CERT_DIR" # Removed chown as it's not needed/might fail in sandbox if user matches

echo "Certificates generated successfully at $CERT_DIR"
