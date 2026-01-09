#!/bin/bash
set -e

# Configuration
BINARY_NAME="AstracatDNS"
SERVICE_NAME="astracat.service"
CONFIG_FILE="config.yaml"
REMOTE_DIR="/opt/astracat"

cd $REMOTE_DIR

# 1. Install Dependencies
echo 'Installing dependencies...'
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y build-essential libunbound-dev unbound-anchor git dnsutils wget tar
else
    echo 'Warning: apt-get not found. Ensure libunbound-dev, git, gcc, wget are installed.'
fi

# 2. Install/Update Go to 1.24.0
GO_VERSION="1.24.0"
echo "Checking Go version..."
needs_install=true
if command -v go >/dev/null 2>&1; then
    current_version=$(go version | awk '{print $3}')
    if [[ "$current_version" == "go$GO_VERSION" ]]; then
        echo "Go $GO_VERSION is already installed."
        needs_install=false
    fi
fi

if [ "$needs_install" = true ]; then
    echo "Installing Go $GO_VERSION..."
    wget -q https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
    ln -sf /usr/local/go/bin/go /usr/bin/go
    rm go$GO_VERSION.linux-amd64.tar.gz
fi

export PATH=$PATH:/usr/local/go/bin

# 3. Extract Source
if [ -f "source_deploy.tar.gz" ]; then
    tar -xzf source_deploy.tar.gz
else
    echo "Error: source_deploy.tar.gz not found!"
    exit 1
fi

# 4. Build
echo 'Building binary...'
env CGO_ENABLED=1 go build -ldflags='-s -w' -o $BINARY_NAME
if [ ! -f $BINARY_NAME ]; then
    echo 'Build failed!'
    exit 1
fi
echo 'Build complete.'

# 5. Generate Root Key for Unbound
if [ ! -f /etc/unbound/root.key ]; then
    mkdir -p /etc/unbound
    unbound-anchor -a /etc/unbound/root.key || true 
    chown -R root:root /etc/unbound
fi

# 6. Stop Service if running
if systemctl is-active --quiet $SERVICE_NAME; then
    systemctl stop $SERVICE_NAME
fi

# 7. Configure System
CONFIG=$REMOTE_DIR/$CONFIG_FILE

# A. Stop Conflicting Services
SERVICES="systemd-resolved bind9 named dnsmasq unbound nginx apache2 httpd"
for SVC in $SERVICES; do
    if systemctl is-active --quiet $SVC; then
        systemctl stop $SVC >/dev/null 2>&1 || true
        systemctl disable $SVC >/dev/null 2>&1 || true
    fi
done

# B. Force Kill Ports
fuser -k -9 53/udp >/dev/null 2>&1 || true
fuser -k -9 53/tcp >/dev/null 2>&1 || true
fuser -k -9 853/tcp >/dev/null 2>&1 || true
fuser -k -9 443/tcp >/dev/null 2>&1 || true

# C. Fix DNS
if grep -q "127.0.0.53" /etc/resolv.conf; then
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
fi

# D. SSL Auto-Discovery
LE_DIR="/etc/letsencrypt/live"
if [ -d "$LE_DIR" ]; then
    DOMAIN=$(ls "$LE_DIR" | head -n 1)
    if [ ! -z "$DOMAIN" ]; then
        CERT_PATH="$LE_DIR/$DOMAIN/fullchain.pem"
        KEY_PATH="$LE_DIR/$DOMAIN/privkey.pem"
        if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
            echo "Found Let's Encrypt certs for $DOMAIN"
            sed -i "s|cert_file:.*|cert_file: \"$CERT_PATH\"|" $CONFIG
            sed -i "s|key_file:.*|key_file: \"$KEY_PATH\"|" $CONFIG
        fi
    fi
fi

# E. Systemd Setup
cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=AstracatDNS Resolver
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$REMOTE_DIR
ExecStart=$REMOTE_DIR/$BINARY_NAME
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

sleep 5
if systemctl is-active --quiet $SERVICE_NAME; then
    echo 'Service is RUNNING.'
    systemctl status $SERVICE_NAME --no-pager
    
    # FUNCTIONAL TEST
    echo -e "\n=== Functional DNS Test ==="
    echo "Querying google.com @127.0.0.1..."
    if command -v dig >/dev/null; then
        RESPONSE=$(dig @127.0.0.1 -p 53 google.com +short +time=2)
        if [ -n "$RESPONSE" ]; then
            echo -e "SUCCESS: Resolved google.com to $RESPONSE"
        else
            echo -e "FAILURE: No response from local DNS server!"
            # Check logs
            journalctl -u $SERVICE_NAME -n 20 --no-pager
            exit 1
        fi
    else
        echo "Warning: 'dig' command not found, skipping functional test."
    fi
else
    echo 'Service FAILED to start.'
    journalctl -u $SERVICE_NAME -n 50 --no-pager
    exit 1
fi
