#!/bin/bash

# Configuration
BINARY_NAME="AstracatDNS"
REMOTE_USER="root"
REMOTE_HOST="your_server_ip" # CHANGE THIS
REMOTE_DIR="/opt/astracat"
CONFIG_FILE="config.yaml"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AstracatDNS Auto-Deploy (Remote Build) ===${NC}"

# 1. Ask for Server IP if not set
if [ -n "$1" ]; then
    REMOTE_HOST="$1"
elif [ "$REMOTE_HOST" == "your_server_ip" ] || [ -z "$REMOTE_HOST" ]; then
    read -p "Enter Remote Server IP: " REMOTE_HOST
fi

if [ -z "$REMOTE_HOST" ]; then
    echo -e "${RED}Error: Remote host IP is required!${NC}"
    exit 1
fi

# 2. Package Source Code
echo -e "${GREEN}[1/5] Packaging source code...${NC}"
# Exclude binary, git, and other non-source files
export COPYFILE_DISABLE=1
tar --exclude='.git' --exclude='bin' --exclude='*.tar.gz' --exclude="$BINARY_NAME" --exclude='._*' -czf source_deploy.tar.gz . 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to package source code!${NC}"
    exit 1
fi

# 3. Create Remote Directory & Upload Files
echo -e "${GREEN}[2/5] Preparing remote environment & Uploading...${NC}"
# Clean directory first to avoid stale files (e.g. old cache implementations)
ssh $REMOTE_USER@$REMOTE_HOST "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"

# Upload source tarball, config, and installation script
scp source_deploy.tar.gz $CONFIG_FILE remote_install.sh $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/

# 4. Execute Remote Installation
echo -e "${GREEN}[3/5] Executing installation on remote server...${NC}"
ssh $REMOTE_USER@$REMOTE_HOST "bash $REMOTE_DIR/remote_install.sh"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}=== Deployment Complete! ===${NC}"
else
    echo -e "${RED}=== Deployment Failed! ===${NC}"
    exit 1
fi

# Clean up local files
rm -f source_deploy.tar.gz