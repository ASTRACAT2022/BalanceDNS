#!/bin/bash

# Configuration
BINARY_NAME="AstracatDNS"
LOCAL_BINARY_NAME="dns-resolver-linux"
REMOTE_USER="root"
REMOTE_HOST="46.8.224.19" # Previously entered IP
REMOTE_DIR="/opt/astracat"
SERVICE_NAME="astracat.service"
CONFIG_FILE="config.yaml"
CERT_DOMAIN="dns.astracat.ru" # Domain for LetsEncrypt certs

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AstracatDNS Auto-Deploy (Local Build Upload) ===${NC}"

# 1. Determine Server IP
# Priority:
# 1. Command-line argument: ./deploy_prod.sh <IP>
# 2. Hardcoded REMOTE_HOST in script
# 3. Interactive prompt

if [ -n "$1" ]; then
    REMOTE_HOST="$1"
fi

if [ -z "$REMOTE_HOST" ] || [ "$REMOTE_HOST" == "your_server_ip" ] || [ "$REMOTE_HOST" == "185.112.59.109" ]; then
    read -p "Enter Remote Server IP: " INPUT_IP
    if [ -n "$INPUT_IP" ]; then
        REMOTE_HOST="$INPUT_IP"
    fi
fi

if [ -z "$REMOTE_HOST" ]; then
    echo -e "${RED}Error: Remote host IP is required!${NC}"
    exit 1
fi

echo -e "Deploying into: ${GREEN}$REMOTE_HOST${NC}"


# 2. Sync Certificates (Optional but recommended)
echo -e "${GREEN}[1/5] Syncing certificates from remote server...${NC}"
mkdir -p cert
if ssh $REMOTE_USER@$REMOTE_HOST "[ -d /etc/letsencrypt/live/$CERT_DOMAIN ]"; then
    echo "Found LetsEncrypt certificates for $CERT_DOMAIN. Downloading..."
    scp $REMOTE_USER@$REMOTE_HOST:/etc/letsencrypt/live/$CERT_DOMAIN/fullchain.pem cert/
    scp $REMOTE_USER@$REMOTE_HOST:/etc/letsencrypt/live/$CERT_DOMAIN/privkey.pem cert/
else
    echo -e "${YELLOW}Remote certificates not found at /etc/letsencrypt/live/$CERT_DOMAIN. Skipping sync.${NC}"
fi

# 3. Local Build
echo -e "${GREEN}[2/5] Building binary locally for Linux/AMD64...${NC}"
rm -f $LOCAL_BINARY_NAME
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o $LOCAL_BINARY_NAME main.go

if [ ! -f "$LOCAL_BINARY_NAME" ]; then
    echo -e "${RED}Local build failed!${NC}"
    exit 1
fi
echo "Binary size: $(du -h $LOCAL_BINARY_NAME | cut -f1)"

# 4. Create Remote Directory & Stop Service
echo -e "${GREEN}[3/5] Preparing remote environment...${NC}"
ssh $REMOTE_USER@$REMOTE_HOST "
    mkdir -p $REMOTE_DIR
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo 'Stopping existing service...'
        systemctl stop $SERVICE_NAME
    fi
"

# 5. Upload Files
echo -e "${GREEN}[4/5] Uploading binary, config, and certificates...${NC}"
scp $LOCAL_BINARY_NAME $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/$BINARY_NAME
scp $CONFIG_FILE $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/$CONFIG_FILE
scp -r cert $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/

# 6. Remote Configuration & Restart
echo -e "${GREEN}[5/5] Configuring and restarting remote service...${NC}"
ssh $REMOTE_USER@$REMOTE_HOST "
    set -e
    cd $REMOTE_DIR
    chmod +x $BINARY_NAME

    # System Tuning / cleanup
    SERVICES=\"systemd-resolved bind9 named dnsmasq unbound nginx apache2 httpd\"
    for SVC in \$SERVICES; do
        if systemctl is-active --quiet \$SVC; then
            systemctl stop \$SVC >/dev/null 2>&1 || true
            systemctl disable \$SVC >/dev/null 2>&1 || true
        fi
    done
    
    # Kill ports
    # Kill ports (forcefully)
    echo "Killing old processes..."
    fuser -k -9 53/udp >/dev/null 2>&1 || true
    fuser -k -9 53/tcp >/dev/null 2>&1 || true
    fuser -k -9 853/tcp >/dev/null 2>&1 || true
    fuser -k -9 443/tcp >/dev/null 2>&1 || true
    fuser -k -9 9090/tcp >/dev/null 2>&1 || true
    fuser -k -9 8080/tcp >/dev/null 2>&1 || true
    
    # Also kill by name in case fuser is missing
    # pkill -f can kill the ssh session itself if the command matches. Use killall.
    killall -9 $BINARY_NAME || true
    
    sleep 2

    # Debug: Check if certificates exist
    echo "Checking certificate paths..."
    ls -la $REMOTE_DIR/cert/ || echo "Directory $REMOTE_DIR/cert/ NOT FOUND"
    
    # Fix DNS locally if needed
    if grep -q \"127.0.0.53\" /etc/resolv.conf; then
        echo \"nameserver 8.8.8.8\" > /etc/resolv.conf
    fi

    # Create Service File
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

# Clean up local binary
rm -f $LOCAL_BINARY_NAME

echo -e "${GREEN}=== Deployment Complete! ===${NC}"
