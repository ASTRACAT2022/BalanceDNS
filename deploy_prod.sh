#!/bin/bash

# Configuration
BINARY_NAME="AstracatDNS"
REMOTE_USER="root"
REMOTE_HOST="your_server_ip" # CHANGE THIS
REMOTE_DIR="/opt/astracat"
SERVICE_NAME="astracat.service"
CONFIG_FILE="config.yaml"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AstracatDNS Auto-Deploy (Remote Build) ===${NC}"

# 1. Ask for Server IP if not set
if [ "$REMOTE_HOST" == "your_server_ip" ]; then
    read -p "Enter Remote Server IP: " REMOTE_HOST
fi

# 2. Package Source Code
echo -e "${GREEN}[1/5] Packaging source code...${NC}"
# Exclude binary, git, and other non-source files
tar --exclude='.git' --exclude='bin' --exclude='*.tar.gz' --exclude="$BINARY_NAME" -czf source_deploy.tar.gz .
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to package source code!${NC}"
    exit 1
fi

# 3. Create Remote Directory & Prepare Environment
echo -e "${GREEN}[2/5] Preparing remote environment & Uploading...${NC}"
ssh $REMOTE_USER@$REMOTE_HOST "mkdir -p $REMOTE_DIR"

scp source_deploy.tar.gz $CONFIG_FILE $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/

# 4. Remote Build & Install
echo -e "${GREEN}[3/5] Building on remote server...${NC}"
ssh $REMOTE_USER@$REMOTE_HOST "
    set -e
    cd $REMOTE_DIR
    
    # Install Dependencies
    echo 'Installing dependencies...'
    if command -v apt-get >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y golang libunbound-dev unbound-anchor git gcc
    else
        echo 'Warning: apt-get not found. Ensure Go and libunbound-dev are installed.'
    fi

    # Extract Source
    tar -xzf source_deploy.tar.gz

    # Init/Update Module if needed (sometimes go.mod is minimal)
    # go mod tidy 

    # Build
    echo 'Building binary...'
    env CGO_ENABLED=1 go build -ldflags='-s -w' -o $BINARY_NAME
    if [ ! -f $BINARY_NAME ]; then
        echo 'Build failed!'
        exit 1
    fi
    echo 'Build complete.'

    # Generate Root Key for Unbound
    if [ ! -f /etc/unbound/root.key ]; then
        mkdir -p /etc/unbound
        unbound-anchor -a /etc/unbound/root.key || true # Ignore exit code 1 (it means sig failed but key creates)
        chown -R root:root /etc/unbound
    fi
    
    # Stop Service if running
    if systemctl is-active --quiet $SERVICE_NAME; then
        systemctl stop $SERVICE_NAME
    fi
    
    # Configure System
    CONFIG=$REMOTE_DIR/$CONFIG_FILE
    
    # A. Stop Conflicting Services
    SERVICES=\"systemd-resolved bind9 named dnsmasq unbound nginx apache2 httpd\"
    for SVC in \$SERVICES; do
        if systemctl is-active --quiet \$SVC; then
            systemctl stop \$SVC >/dev/null 2>&1 || true
            systemctl disable \$SVC >/dev/null 2>&1 || true
        fi
    done
    
    # B. Force Kill Ports
    fuser -k -9 53/udp >/dev/null 2>&1 || true
    fuser -k -9 53/tcp >/dev/null 2>&1 || true
    fuser -k -9 853/tcp >/dev/null 2>&1 || true
    fuser -k -9 443/tcp >/dev/null 2>&1 || true
    
    # C. Fix DNS
    if grep -q \"127.0.0.53\" /etc/resolv.conf; then
        echo \"nameserver 8.8.8.8\" > /etc/resolv.conf
    fi

    # D. SSL Auto-Discovery
    LE_DIR=\"/etc/letsencrypt/live\"
    FOUND=0
    if [ -d \"\$LE_DIR\" ]; then
        DOMAIN=\$(ls \"\$LE_DIR\" | head -n 1)
        if [ ! -z \"\$DOMAIN\" ]; then
            CERT_PATH=\"\$LE_DIR/\$DOMAIN/fullchain.pem\"
            KEY_PATH=\"\$LE_DIR/\$DOMAIN/privkey.pem\"
            if [ -f \"\$CERT_PATH\" ] && [ -f \"\$KEY_PATH\" ]; then
                sed -i \"s|cert_file:.*|cert_file: \\\"\$CERT_PATH\\\"|\" \$CONFIG
                sed -i \"s|key_file:.*|key_file: \\\"\$KEY_PATH\\\"|\" \$CONFIG
                FOUND=1
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
    
    sleep 3
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo 'Service is RUNNING.'
        systemctl status $SERVICE_NAME --no-pager
    else
        echo 'Service FAILED to start.'
        journalctl -u $SERVICE_NAME -n 50 --no-pager
        exit 1
    fi
"

# Clean up local tarball
rm -f source_deploy.tar.gz

echo -e "${GREEN}=== Deployment Complete! ===${NC}"
