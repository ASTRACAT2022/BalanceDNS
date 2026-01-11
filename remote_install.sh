#!/bin/bash
set -e

# Configuration
BINARY_NAME="AstracatDNS"
SERVICE_NAME="astracat.service"
KRESD_SERVICE="kresd@1.service" # Encapsulated instance
CONFIG_FILE="config.yaml"
REMOTE_DIR="/opt/astracat"

cd $REMOTE_DIR

# 0. Fix DNS for Deployment
# Ensure we have a working resolver for apt/wget
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# 1. Cleaning up legacy DNS and Installing Dependencies
echo 'Preparing environment...'
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    
    # Stop and remove Unbound daemon if present (we use embedded libunbound, but daemon might conflict on 53 if active)
    # Actually, we WANT standard unbound daemon GONE, but libunbound-dev installed.
    echo "Checking for legacy Unbound daemon..."
    if systemctl is-active --quiet unbound; then
        echo "Stopping Unbound service..."
        systemctl stop unbound || true
        systemctl disable unbound || true
    fi

    # Stop Knot Resolver if present (legacy from previous install)
    if systemctl is-active --quiet 'kresd@1.service'; then
        echo "Stopping Knot Resolver..."
        systemctl stop 'kresd@*' || true
        systemctl disable 'kresd@*' || true
    fi

    echo "Removing legacy DNS packages (Knot Resolver)..."
    apt-get purge -y knot-resolver || true
    apt-get autoremove -y || true
    
    # We DO NOT remove libunbound-dev if we need it for our app.
    # But we remove 'unbound' daemon package if possible to avoid conflict, 
    # though libunbound-dev might depend on libs.
    # Just ensure service is stopped.
    
    apt-get update
    # Install libunbound-dev and Go dependencies
    echo "Installing libunbound-dev and dependencies..."
    apt-get install -y build-essential git dnsutils wget tar libunbound-dev dns-root-data
else
    echo 'Warning: apt-get not found. Ensure libunbound-dev is installed manually.'
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
echo 'Building Control Plane binary...'
# CGO_ENABLED=1 because we use libunbound
env CGO_ENABLED=1 go build -ldflags='-s -w' -o $BINARY_NAME
if [ ! -f $BINARY_NAME ]; then
    echo 'Build failed!'
    exit 1
fi
echo 'Build complete.'

# 5. Stop Services & Cleanup
echo "Stopping existing services..."
# Stop Astracat Control Plane
if systemctl is-active --quiet $SERVICE_NAME; then
    systemctl stop $SERVICE_NAME
fi

# Stop Knot (Legacy cleanup)
systemctl stop 'kresd@*' || true

# Check for systemd-resolved and disable it
if systemctl is-active --quiet systemd-resolved; then
    echo "Disabling systemd-resolved to free up port 53..."
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
fi

# Prepare Unbound Root Key (Criticial for DNSSEC)
echo "Setting up DNSSEC Trust Anchor..."
mkdir -p /var/lib/unbound
if [ -f /usr/share/dns/root.key ]; then
    cp /usr/share/dns/root.key /var/lib/unbound/root.key
elif [ ! -f /var/lib/unbound/root.key ]; then
    # Download if missing and no system key
    wget -O /var/lib/unbound/root.key https://www.internic.net/domain/named.root.key || true
fi
# Ensure unbound-anchor updates it if installed
if command -v unbound-anchor >/dev/null; then
    unbound-anchor -a /var/lib/unbound/root.key || true
fi
chmod 644 /var/lib/unbound/root.key

# Stop other potential conflicting services
SERVICES="bind9 named dnsmasq unbound nginx apache2 httpd"
for SVC in $SERVICES; do
    if systemctl is-active --quiet $SVC; then
        systemctl stop $SVC >/dev/null 2>&1 || true
        systemctl disable $SVC >/dev/null 2>&1 || true
    fi
done

# Force Kill Ports to ensure they are free
echo "Force cleaning ports..."
PORTS="53 443 853 5353"
for PORT in $PORTS; do
    fuser -k -9 $PORT/tcp >/dev/null 2>&1 || true
    fuser -k -9 $PORT/udp >/dev/null 2>&1 || true
done
# Give the kernel a moment to release ports
sleep 2

# 6. Configure Systemd
cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=AstracatDNS Control Plane
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$REMOTE_DIR
ExecStart=$REMOTE_DIR/$BINARY_NAME
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 7. Start Services
echo 'Starting AstracatDNS Control Plane...'
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

sleep 2

# 8. Verify
if systemctl is-active --quiet $SERVICE_NAME; then
    echo 'Control Plane is RUNNING.'
    systemctl status $SERVICE_NAME --no-pager
    
    echo -e "\n=== Functional DNS Test ==="
    echo "Querying google.com @127.0.0.1 (Frontend 53)..."
    if command -v dig >/dev/null; then
        echo "Waiting for DNS to be ready..."
        # Retry up to 10 times
        for i in {1..10}; do
            RESPONSE=$(dig @127.0.0.1 -p 53 google.com +short +time=2 || true)
            if [ -n "$RESPONSE" ]; then
                echo -e "SUCCESS: Resolved google.com to $RESPONSE"
                break
            fi
            echo "Attempt $i: No response yet, retrying in 2s..."
            sleep 2
        done

        if [ -z "$RESPONSE" ]; then
            echo -e "FAILURE: No response from local DNS server after multiple attempts!"
            echo "Checking Control Plane logs:"
            journalctl -u $SERVICE_NAME -n 20 --no-pager
            exit 1
        fi
    fi
else
    echo 'Control Plane FAILED to start.'
    journalctl -u $SERVICE_NAME -n 50 --no-pager
    exit 1
fi
