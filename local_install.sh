#!/bin/bash
set -e

# Configuration
BINARY_NAME="AstracatDNS"
SERVICE_NAME="astracat.service"
INSTALL_DIR="/opt/astracat"
CONFIG_FILE="config.yaml"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AstracatDNS Local Installation ===${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root (sudo ./local_install.sh)${NC}"
  exit 1
fi

# 1. Prepare Environment
echo -e "${GREEN}[1/5] Preparing environment...${NC}"

# Fix DNS for valid downloads if broken
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# Dependencies
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # Install dependencies
    apt-get install -y build-essential git dnsutils wget tar libunbound-dev dns-root-data
    
    # Disable conflicting services
    SERVICES="unbound knot-resolver systemd-resolved bind9 named dnsmasq nginx apache2"
    for SVC in $SERVICES; do
        if systemctl is-active --quiet $SVC; then
            echo "Stopping $SVC..."
            systemctl stop $SVC || true
            systemctl disable $SVC || true
        fi
    done
fi

# 2. Setup Install Directory
echo -e "${GREEN}[2/5] Setting up directory $INSTALL_DIR...${NC}"
mkdir -p $INSTALL_DIR
# Copy current files to install dir
cp -r ./* $INSTALL_DIR/
cd $INSTALL_DIR

# 3. Setup Go (if needed)
GO_VERSION="1.24.0"
if ! command -v go >/dev/null 2>&1 || [[ "$(go version)" != *"go$GO_VERSION"* ]]; then
    echo "Installing/Updating Go $GO_VERSION..."
    wget -q https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go$GO_VERSION.linux-amd64.tar.gz
    ln -sf /usr/local/go/bin/go /usr/bin/go
    rm go$GO_VERSION.linux-amd64.tar.gz
fi
export PATH=$PATH:/usr/local/go/bin

# 4. Build
echo -e "${GREEN}[3/5] Building binary...${NC}"
env CGO_ENABLED=1 go build -ldflags='-s -w' -o $BINARY_NAME
if [ ! -f $BINARY_NAME ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# 4.1 Setup Certificates
echo "Checking for custom certificates..."
if [ -f "internal/config/myceeert/fullchain.pem" ] && [ -f "internal/config/myceeert/privkey.pem" ]; then
    echo "Found custom certificates in internal/config/myceeert. Installing..."
    cp "internal/config/myceeert/fullchain.pem" "cert.pem"
    cp "internal/config/myceeert/privkey.pem" "key.pem"
    chmod 644 cert.pem
    chmod 600 key.pem
    echo "Certificates installed."
else
    echo "No custom certificates found in internal/config/myceeert. Will use self-signed generation."
fi

# 5. Configure Systemd
echo -e "${GREEN}[4/5] Configuring Service...${NC}"

# Setup DNSSEC Root Key
mkdir -p /var/lib/unbound
wget -O /var/lib/unbound/root.key https://www.internic.net/domain/named.root.key || true
chmod 644 /var/lib/unbound/root.key

# Force clean ports
fuser -k -9 53/tcp 53/udp 443/tcp 853/tcp >/dev/null 2>&1 || true

cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=AstracatDNS Control Plane
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 6. Start
echo -e "${GREEN}[5/5] Starting Service...${NC}"
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

sleep 5

if systemctl is-active --quiet $SERVICE_NAME; then
    echo -e "${GREEN}=== Installation Complete! Service IS RUNNING. ===${NC}"
    systemctl status $SERVICE_NAME --no-pager
else
    echo -e "${RED}=== Service Failed to Start ===${NC}"
    journalctl -u $SERVICE_NAME -n 50 --no-pager
    exit 1
fi
