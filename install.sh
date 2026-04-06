#!/bin/bash
###############################################################################
# BalanceDNS - Automatic Installer
# 
# This script does EVERYTHING automatically:
# 1. Compiles BalanceDNS from source
# 2. Creates system user and directories
# 3. Generates configuration
# 4. Installs systemd service + watchdog
# 5. Installs health check monitoring
# 6. Starts and verifies the service
#
# Usage: sudo ./install.sh [--config-only] [--skip-build]
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Parse arguments
CONFIG_ONLY=false
SKIP_BUILD=false
for arg in "$@"; do
    case $arg in
        --config-only) CONFIG_ONLY=true ;;
        --skip-build) SKIP_BUILD=true ;;
    esac
done

# Configuration - CHANGE THESE FOR YOUR SERVER
DEFAULT_SERVER_IP=$(hostname -I | awk '{print $1}')
read -p "Enter server IP address [$DEFAULT_SERVER_IP]: " SERVER_IP
SERVER_IP=${SERVER_IP:-$DEFAULT_SERVER_IP}

# Default upstream DNS servers
DEFAULT_UPSTREAM_1="95.85.95.95:53"
DEFAULT_UPSTREAM_2="2.56.220.2:53"
DEFAULT_UPSTREAM_RU="77.88.8.8:53"

read -p "Primary upstream DNS [$DEFAULT_UPSTREAM_1]: " UPSTREAM_1
UPSTREAM_1=${UPSTREAM_1:-$DEFAULT_UPSTREAM_1}

read -p "Secondary upstream DNS [$DEFAULT_UPSTREAM_2]: " UPSTREAM_2
UPSTREAM_2=${UPSTREAM_2:-$DEFAULT_UPSTREAM_2}

read -p "Russian zone upstream [$DEFAULT_UPSTREAM_RU]: " UPSTREAM_RU
UPSTREAM_RU=${UPSTREAM_RU:-$DEFAULT_UPSTREAM_RU}

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
INSTALL_DIR="/usr/sbin"
CONFIG_DIR="/etc"
DATA_DIR="/var/lib/balancedns"
LOG_DIR="/var/log"
USER="balancedns"
GROUP="balancedns"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}  ${BOLD}BalanceDNS Automatic Installer${NC}                          ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}Configuration Summary:${NC}"
echo -e "  ${CYAN}Server IP:${NC}          $SERVER_IP"
echo -e "  ${CYAN}Primary upstream:${NC}   $UPSTREAM_1"
echo -e "  ${CYAN}Secondary upstream:${NC} $UPSTREAM_2"
echo -e "  ${CYAN}Russian zone upstream:${NC} $UPSTREAM_RU"
echo ""

# Check if root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}✗ This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Step counter
STEP=0
TOTAL_STEPS=10

print_step() {
    STEP=$((STEP + 1))
    echo ""
    echo -e "${BOLD}${BLUE}[${STEP}/${TOTAL_STEPS}]${NC} $1"
    echo -e "${BLUE}────────────────────────────────────────────────────────${NC}"
}

success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

error() {
    echo -e "  ${RED}✗${NC} $1"
}

###############################################################################
# Step 1: Install build dependencies
###############################################################################
print_step "Installing build dependencies"

if command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq build-essential pkg-config libssl-dev dig curl dnsutils 2>/dev/null | tail -n 5
    success "Installed Debian/Ubuntu dependencies"
elif command -v yum &> /dev/null; then
    yum install -y epel-release 2>/dev/null || true
    yum install -y gcc gcc-c++ make pkgconfig openssl-devel bind-utils curl 2>/dev/null | tail -n 5
    success "Installed CentOS/RHEL dependencies"
else
    warn "Unknown package manager - you may need to install dependencies manually"
fi

###############################################################################
# Step 2: Compile BalanceDNS
###############################################################################
if [[ "$CONFIG_ONLY" == true ]]; then
    print_step "Skipping compilation (config-only mode)"
    warn "Assuming binary is already installed at $INSTALL_DIR/balancedns"
else
    if [[ "$SKIP_BUILD" == false ]]; then
        print_step "Compiling BalanceDNS from source"
        
        if [[ ! -f "$PROJECT_DIR/Cargo.toml" ]]; then
            error "Cargo.toml not found in $PROJECT_DIR"
            error "Please run this script from the BalanceDNS source directory"
            exit 1
        fi
        
        cd "$PROJECT_DIR"
        
        # Check if Rust is installed
        if ! command -v cargo &> /dev/null; then
            echo -e "  ${YELLOW}Rust not found, installing...${NC}"
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
        fi
        
        echo -e "  Building release binary..."
        cargo build --release 2>&1 | tail -n 10
        
        if [[ -f "$PROJECT_DIR/target/release/balancedns" ]]; then
            success "Compilation successful"
        else
            error "Compilation failed!"
            exit 1
        fi
    else
        print_step "Skipping compilation (skip-build mode)"
    fi
fi

###############################################################################
# Step 3: Create system user and directories
###############################################################################
print_step "Creating system user and directories"

# Create user if not exists
if ! id "$USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
    success "Created system user: $USER"
else
    warn "User $USER already exists"
fi

# Create directories
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/tls"
mkdir -p "$LOG_DIR"
chown -R "$USER:$GROUP" "$DATA_DIR"
chmod 755 "$DATA_DIR"
success "Created data directory: $DATA_DIR"

# Generate self-signed TLS certificate if not exists
if [[ ! -f "$DATA_DIR/tls/server.crt" ]]; then
    echo -e "  Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 -keyout "$DATA_DIR/tls/server.key" \
        -out "$DATA_DIR/tls/server.crt" -days 3650 -nodes \
        -subj "/CN=$SERVER_IP" 2>/dev/null
    chmod 640 "$DATA_DIR/tls/server.key"
    chmod 644 "$DATA_DIR/tls/server.crt"
    chown -R "$USER:$GROUP" "$DATA_DIR/tls"
    success "Generated TLS certificate"
else
    warn "TLS certificate already exists"
fi

###############################################################################
# Step 4: Install binary
###############################################################################
if [[ "$CONFIG_ONLY" == false ]]; then
    print_step "Installing BalanceDNS binary"
    
    if [[ -f "$PROJECT_DIR/target/release/balancedns" ]]; then
        cp "$PROJECT_DIR/target/release/balancedns" "$INSTALL_DIR/balancedns"
        chmod 755 "$INSTALL_DIR/balancedns"
        success "Installed binary to $INSTALL_DIR/balancedns"
        
        # Show version
        BALANCEDNS_VERSION=$("$INSTALL_DIR/balancedns" --version 2>&1 | head -n 1) || true
        if [[ -n "$BALANCEDNS_VERSION" ]]; then
            echo -e "  Version: $BALANCEDNS_VERSION"
        fi
    else
        warn "Binary not found at $PROJECT_DIR/target/release/balancedns"
        warn "Assuming binary is already installed"
    fi
else
    print_step "Skipping binary installation (config-only mode)"
fi

###############################################################################
# Step 5: Generate configuration
###############################################################################
print_step "Generating configuration file"

CONFIG_FILE="$CONFIG_DIR/balancedns.toml"
BACKUP_FILE="$CONFIG_FILE.bak.$(date +%Y%m%d%H%M%S)"

# Backup existing config
if [[ -f "$CONFIG_FILE" ]]; then
    cp "$CONFIG_FILE" "$BACKUP_FILE"
    warn "Backed up existing config to $BACKUP_FILE"
fi

# Generate new config
cat > "$CONFIG_FILE" << EOF
###############################################################################
# BalanceDNS Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Server IP: $SERVER_IP
###############################################################################

[server]
# DNS listeners
udp_listen = "${SERVER_IP}:53"
tcp_listen = "${SERVER_IP}:53"
dot_listen = "${SERVER_IP}:853"
doh_listen = "${SERVER_IP}:443"

[tls]
# TLS certificates for DoT/DoH
cert_pem = "${DATA_DIR}/tls/server.crt"
key_pem = "${DATA_DIR}/tls/server.key"

[balancing]
# Load balancing algorithm: fastest, round_robin, random
algorithm = "fastest"

[security]
# Security settings
deny_any = true
deny_dnskey = true
request_timeout_ms = 500

[cache]
# DNS cache settings
enabled = true
max_size = 100000
ttl_seconds = 7200
min_ttl = 60
max_ttl = 86400
decrement_ttl = true

[metrics]
# Prometheus metrics endpoint
listen = "127.0.0.1:9100"

[global]
# Performance settings
threads_udp = 8
threads_tcp = 4
max_tcp_clients = 4096
max_waiting_clients = 1000000
max_active_queries = 200000
max_clients_waiting_for_query = 2000

[hosts_local]
# Local host overrides (uncomment to use)
# "example.com." = "1.2.3.4"

[hosts_remote]
# Remote hosts list (updated periodically)
url = "https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/refs/heads/main/bypass"
refresh_seconds = 300
ttl_seconds = 300

[blocklist_remote]
# Remote blocklist (ad blocking)
url = "https://raw.githubusercontent.com/Zalexanninev15/NoADS_RU/main/ads_list.txt"
refresh_seconds = 600

[plugins]
# Plugin libraries (leave empty if not using plugins)
libraries = []

# Upstream DNS servers
[[upstreams]]
name = "upstream-1"
proto = "udp"
addr = "${UPSTREAM_1}"
pool = "default"
weight = 5

[[upstreams]]
name = "upstream-2"
proto = "udp"
addr = "${UPSTREAM_2}"
pool = "default"
weight = 5

[[upstreams]]
name = "upstream-yandex"
proto = "udp"
addr = "${UPSTREAM_RU}"
pool = "ru-zone"
weight = 1

# Routing rules
[[routing_rules]]
suffix = "."
upstreams = ["upstream-1", "upstream-2"]

[[routing_rules]]
suffix = ".ru."
upstreams = ["upstream-yandex"]
EOF

success "Generated config at $CONFIG_FILE"
echo -e "  You can edit it later with: nano $CONFIG_FILE"

###############################################################################
# Step 6: Install systemd service files
###############################################################################
print_step "Installing systemd service files"

# Copy service file
if [[ -f "$SCRIPT_DIR/balancedns.service" ]]; then
    cp "$SCRIPT_DIR/balancedns.service" /etc/systemd/system/balancedns.service
    success "Installed balancedns.service"
else
    error "balancedns.service not found!"
    exit 1
fi

# Copy health check service and timer
if [[ -f "$SCRIPT_DIR/balancedns-healthcheck.service" ]]; then
    cp "$SCRIPT_DIR/balancedns-healthcheck.service" /etc/systemd/system/
    success "Installed balancedns-healthcheck.service"
fi

if [[ -f "$SCRIPT_DIR/balancedns-healthcheck.timer" ]]; then
    cp "$SCRIPT_DIR/balancedns-healthcheck.timer" /etc/systemd/system/
    success "Installed balancedns-healthcheck.timer"
fi

# Reload systemd
systemctl daemon-reload
success "Reloaded systemd daemon"

###############################################################################
# Step 7: Install monitoring scripts
###############################################################################
print_step "Installing monitoring scripts"

# Install health check script
if [[ -f "$SCRIPT_DIR/scripts/healthcheck.sh" ]]; then
    # Update DNS server IP in healthcheck
    sed "s/DNS_SERVER=\"[0-9.]*\"/DNS_SERVER=\"$SERVER_IP\"/" \
        "$SCRIPT_DIR/scripts/healthcheck.sh" > /tmp/balancedns-healthcheck.sh
    cp /tmp/balancedns-healthcheck.sh /usr/local/bin/balancedns-healthcheck.sh
    chmod +x /usr/local/bin/balancedns-healthcheck.sh
    rm -f /tmp/balancedns-healthcheck.sh
    success "Installed health check script"
else
    error "scripts/healthcheck.sh not found!"
    exit 1
fi

# Install status script
if [[ -f "$SCRIPT_DIR/scripts/status.sh" ]]; then
    sed "s/DNS_SERVER=\"[0-9.]*\"/DNS_SERVER=\"$SERVER_IP\"/" \
        "$SCRIPT_DIR/scripts/status.sh" > /tmp/status.sh
    sed -i "s|METRICS_URL=\"http://[0-9.:]*|METRICS_URL=\"http://127.0.0.1:9100|" /tmp/status.sh
    cp /tmp/status.sh "$SCRIPT_DIR/scripts/status.sh"
    chmod +x "$SCRIPT_DIR/scripts/status.sh"
    success "Installed status script"
fi

# Install monitor script
if [[ -f "$SCRIPT_DIR/scripts/monitor.sh" ]]; then
    sed -i "s/DNS_SERVER=\"[0-9.]*\"/DNS_SERVER=\"$SERVER_IP\"/" "$SCRIPT_DIR/scripts/monitor.sh"
    sed -i "s|METRICS_URL=\"http://[0-9.:]*|METRICS_URL=\"http://127.0.0.1:9100|" "$SCRIPT_DIR/scripts/monitor.sh"
    success "Installed monitor script"
fi

# Create log file
touch "$LOG_DIR/balancedns-healthcheck.log"
chmod 644 "$LOG_DIR/balancedns-healthcheck.log"
success "Created health check log file"

###############################################################################
# Step 8: Enable and start services
###############################################################################
print_step "Enabling and starting services"

# Stop existing service if running
systemctl stop balancedns 2>/dev/null || true
systemctl stop balancedns-healthcheck.timer 2>/dev/null || true

# Enable services
systemctl enable balancedns.service 2>/dev/null || true
systemctl enable balancedns-healthcheck.timer 2>/dev/null || true
success "Enabled services"

# Start services
systemctl start balancedns.service
sleep 2
systemctl start balancedns-healthcheck.timer
success "Started services"

###############################################################################
# Step 9: Verify installation
###############################################################################
print_step "Verifying installation"

# Check if service is running
sleep 3
if systemctl is-active --quiet balancedns; then
    success "Service is running"
    
    # Check if DNS is responding
    sleep 2
    if dig +short +time=2 +tries=1 @$SERVER_IP localhost A &>/dev/null; then
        success "DNS server is responding on $SERVER_IP:53"
    else
        warn "DNS server not yet responding (may still be starting up)"
    fi
else
    error "Service failed to start!"
    echo ""
    echo -e "${YELLOW}Service logs:${NC}"
    journalctl -u balancedns --no-pager -n 20
    echo ""
    echo -e "${YELLOW}Trying to diagnose the issue...${NC}"
    
    # Check config
    if ! "$INSTALL_DIR/balancedns" --config "$CONFIG_FILE" --test 2>/dev/null; then
        error "Configuration file has errors"
        echo -e "  Edit the config: nano $CONFIG_FILE"
        echo -e "  Test it: $INSTALL_DIR/balancedns --config $CONFIG_FILE --test"
    fi
fi

# Check health check
if systemctl is-active --quiet balancedns-healthcheck.timer; then
    success "Health check timer is active"
else
    warn "Health check timer not active"
fi

###############################################################################
# Step 10: Show summary
###############################################################################
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}  ${BOLD}Installation Complete!${NC}                                    ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}What was installed:${NC}"
echo -e "  ${GREEN}✓${NC} BalanceDNS compiled and installed"
echo -e "  ${GREEN}✓${NC} Configuration generated at $CONFIG_FILE"
echo -e "  ${GREEN}✓${NC} Systemd service with watchdog"
echo -e "  ${GREEN}✓${NC} Health check monitoring (every 30s)"
echo -e "  ${GREEN}✓${NC} Auto-restart on failure"
echo ""
echo -e "${BOLD}Service Information:${NC}"
echo -e "  ${CYAN}DNS Server:${NC}    $SERVER_IP:53 (UDP/TCP)"
echo -e "  ${CYAN}DoT Server:${NC}    $SERVER_IP:853"
echo -e "  ${CYAN}DoH Server:${NC}    https://$SERVER_IP:443/dns-query"
echo -e "  ${CYAN}Metrics:${NC}       http://127.0.0.1:9100/metrics"
echo ""
echo -e "${BOLD}Useful Commands:${NC}"
echo -e "  ${YELLOW}Status:${NC}         systemctl status balancedns"
echo -e "  ${YELLOW}Quick status:${NC}   $SCRIPT_DIR/scripts/status.sh"
echo -e "  ${YELLOW}Monitor:${NC}        $SCRIPT_DIR/scripts/monitor.sh"
echo -e "  ${YELLOW}Logs:${NC}           journalctl -u balancedns -f"
echo -e "  ${YELLOW}Health logs:${NC}    tail -f $LOG_DIR/balancedns-healthcheck.log"
echo -e "  ${YELLOW}Restart:${NC}        systemctl restart balancedns"
echo -e "  ${YELLOW}Edit config:${NC}    nano $CONFIG_FILE"
echo ""
echo -e "${BOLD}Testing Your DNS Server:${NC}"
echo -e "  dig @$SERVER_IP google.com A"
echo -e "  dig @$SERVER_IP ya.ru A"
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}Your DNS server is now running with automatic monitoring!${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
echo ""
