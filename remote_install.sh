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
    
    # Stop and remove Unbound if present to avoid conflicts
    echo "Checking for legacy Unbound installation..."
    if systemctl is-active --quiet unbound; then
        echo "Stopping Unbound..."
        systemctl stop unbound || true
        systemctl disable unbound || true
    fi

    echo "Removing legacy DNS packages (Unbound)..."
    # We remove unbound and related dev packages to ensure clean slate for Knot
    apt-get remove -y unbound unbound-anchor libunbound-dev || true
    apt-get autoremove -y || true

    apt-get update
    # Install Knot Resolver and Go dependencies
    echo "Installing Knot Resolver and dependencies..."
    apt-get install -y build-essential git dnsutils wget tar knot-resolver
else
    echo 'Warning: apt-get not found. Ensure knot-resolver is installed manually.'
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
env CGO_ENABLED=0 go build -ldflags='-s -w' -o $BINARY_NAME
if [ ! -f $BINARY_NAME ]; then
    echo 'Build failed!'
    exit 1
fi
echo 'Build complete.'

# 5. Stop Services & Cleanup
# 5. Stop Services & Cleanup
echo "Stopping existing services..."
# Stop Astracat Control Plane
if systemctl is-active --quiet $SERVICE_NAME; then
    systemctl stop $SERVICE_NAME
fi

# Stop Knot Resolver instances
systemctl stop 'kresd@*' || true
systemctl stop kresd.target || true

# Stop systemd-resolved to free up port 53
systemctl stop systemd-resolved || true
systemctl disable systemd-resolved || true

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

# 6. Configure Knot Resolver
echo 'Configuring Knot Resolver...'
mkdir -p /etc/knot-resolver

# Bootstrap minimal config to ensure kresd can start even before AstracatDNS runs
cat > /etc/knot-resolver/kresd.conf <<EOF
-- Bootstrap Config
modules = { 'stats', 'policy' }
cache.size = 1024 * 1024 * 1024
net.listen('127.0.0.1', 5353, { kind = 'dns' })
net.listen('/run/knot-resolver/control.sock', 0, { kind = 'control' })
-- policy.add(policy.all(policy.FORWARD('1.1.1.1'))) -- Removed for recursion
EOF
# Create empty policy file to satisfy bootstrap
touch /etc/knot-resolver/policy.lua

# Ensure permissions are correct for knot-resolver user
chown -R root:knot-resolver /etc/knot-resolver
chmod 640 /etc/knot-resolver/kresd.conf
chmod 640 /etc/knot-resolver/policy.lua

# 7. Systemd Setup for Control Plane
cat > /etc/systemd/system/$SERVICE_NAME <<EOF
[Unit]
Description=AstracatDNS Control Plane
After=network.target kresd.target

[Service]
Type=simple
User=root
WorkingDirectory=$REMOTE_DIR
ExecStart=$REMOTE_DIR/$BINARY_NAME
Restart=always
RestartSec=5
# Note: ReadWritePaths removed to avoid namespace issues. Root has access to /run/knot-resolver.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 8. Start Services
echo 'Starting Knot Resolver...'
# Fix Runtime Directory for kresd (distro-preconfig expects /run/knot-resolver/control)
mkdir -p /run/knot-resolver/control
chown -R knot-resolver:knot-resolver /run/knot-resolver
chmod 750 /run/knot-resolver

# Clean up any potential corrupt/oversized cache from previous attempts
rm -rf /var/cache/knot-resolver/*

# Enable and start the first instance of kresd
if ! systemctl enable --now $KRESD_SERVICE; then
    echo "Failed to start $KRESD_SERVICE"
    systemctl status $KRESD_SERVICE --no-pager
    journalctl -xeu $KRESD_SERVICE --no-pager
    exit 1
fi

echo 'Starting AstracatDNS Control Plane...'
# We restart to trigger config generation
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME
# Reload kresd to pick up the config generated by AstracatDNS
sleep 2
# Reload kresd to pick up the config generated by AstracatDNS
sleep 2
if ! systemctl reload-or-restart $KRESD_SERVICE; then
    echo "Failed to reload/restart $KRESD_SERVICE after config update"
    systemctl status $KRESD_SERVICE --no-pager
    journalctl -xeu $KRESD_SERVICE --no-pager
    echo "=== Generated Config Content ==="
    cat /etc/knot-resolver/kresd.conf
    exit 1
fi

# Check if Kresd is actually listening on 5353
echo "Checking listening ports..."
ss -lpn | grep 5353 || echo "Nothing listening on 5353!"

sleep 5

# 9. Verify
if systemctl is-active --quiet $SERVICE_NAME; then
    echo 'Control Plane is RUNNING.'
    systemctl status $SERVICE_NAME --no-pager
    
    echo -e "\n=== Functional DNS Test via Knot Resolver ==="
    echo "Querying Backend directly (5353)..."
    dig @127.0.0.1 -p 5353 google.com +short +time=2 || echo "Backend 5353 FAILED"

    echo "Querying google.com @127.0.0.1 (Frontend 53)..."
    if command -v dig >/dev/null; then
        RESPONSE=$(dig @127.0.0.1 -p 53 google.com +short +time=2)
        if [ -n "$RESPONSE" ]; then
            echo -e "SUCCESS: Resolved google.com to $RESPONSE"
        else
            echo -e "FAILURE: No response from local DNS server!"
            echo "Checking Kresd status:"
            systemctl status $KRESD_SERVICE --no-pager
            echo "Checking listening ports (again):"
            ss -lpn | grep 5353
            echo "Checking generated config:"
            cat /etc/knot-resolver/kresd.conf
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
