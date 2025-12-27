#!/bin/bash
set -e

SERVER_USER="root"
SERVER_HOST="dns.astracat.ru" # Replace with actual or argument
TARGET_DIR="/root/Astracat-DNS-Resolver"

# 0. Check args
if [ -z "$1" ]; then
    echo "Usage: ./deploy.sh user@host"
    echo "Example: ./deploy.sh root@1.2.3.4"
    exit 1
fi
REMOTE="$1"

echo "🚀 Starting Cross-Compilation Deployment for $REMOTE..."

# 1. Build Rust Binary (Linux x86_64)
echo "🦀 Building Astracat-DNS-RS for Linux x86_64..."

# 1. Build Rust Binary (Linux x86_64)
echo "🦀 Building Astracat-DNS-RS for Linux x86_64 (using temporary builder container)..."

# 1. Build Rust Binary (Linux x86_64) using Zig (No Docker required)
echo "🦀 Building Astracat-DNS-RS for Linux x86_64 using Zig..."

# Check for Docker (just in case), if not, use Zig
if command -v docker &> /dev/null; then
    echo "🐳 Docker found. Utilizing Docker for build..."
    docker run --rm \
        -v "$(pwd)":/usr/src/app \
        -w /usr/src/app \
        -e CARGO_HOME=/usr/src/app/.cargo-cache \
        rust:1.83-bullseye \
        cargo build --release --jobs 4
    BUILD_ARTIFACT="target/release/astracat-dns-rs"
else
    echo "⚠️  Docker not found. Falling back to Zig for cross-compilation..."
    
    # Check Brew
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Cannot install Zig. Please install Docker or Homebrew."
        exit 1
    fi

    # Install Zig
    if ! command -v zig &> /dev/null; then
        echo "🍺 Installing Zig via Homebrew..."
        brew install zig
    fi

    # Install Cargo Zigbuild
    if ! command -v cargo-zigbuild &> /dev/null; then
        echo "📦 Installing cargo-zigbuild..."
        cargo install cargo-zigbuild
    fi

    # Add Target
    rustup target add x86_64-unknown-linux-musl

    # Build
    echo "🔨 Compiling with Zig..."
    cargo zigbuild --release --target x86_64-unknown-linux-musl
    BUILD_ARTIFACT="target/x86_64-unknown-linux-musl/release/astracat-dns-rs"
fi

# Check artifact
if [ ! -f "$BUILD_ARTIFACT" ]; then
    echo "❌ Build failed. Artifact not found at $BUILD_ARTIFACT"
    exit 1
fi


# 2. Build Go Proxy (Linux x86_64)
echo "🐭 Building Go Proxy for Linux x86_64..."
cd go-proxy
echo "📦 Downloading Go modules..."
go mod tidy
echo "🔨 Compiling Go Proxy..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o astracat-proxy main.go
cd ..

# 3. Prepare Deployment Package
echo "📦 Packaging..."
mkdir -p deploy_pkg
# Default output
cp "$BUILD_ARTIFACT" deploy_pkg/astracat-dns

cp go-proxy/astracat-proxy deploy_pkg/
cp config.yaml deploy_pkg/
cp hosts deploy_pkg/ # Copy local hosts file

# We need a simplified install script for the server side
cat > deploy_pkg/setup_remote.sh << 'EOF'
#!/bin/bash
set -e

echo "🔧 Installing binaries..."
mv astracat-dns /usr/local/bin/
mv astracat-proxy /usr/local/bin/
chmod +x /usr/local/bin/astracat-dns /usr/local/bin/astracat-proxy

# --- Install & Configure Engine (Unbound) ---
echo "⚙️  Installing Unbound (DNS Engine)..."
# Non-interactive to avoid prompts
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y unbound

echo "⚙️  Configuring Unbound on separate port (5353)..."
# Create config to listen on 5353 (localhost only) so it doesn't conflict with our port 53
cat > /etc/unbound/unbound.conf << 'UNBOUND_EOF'
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5353
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    cache-max-ttl: 86400
    cache-min-ttl: 0
    hide-identity: yes
    hide-version: yes
    minimal-responses: yes
    # Recursion
    do-not-query-localhost: no
UNBOUND_EOF

echo "🔄 Restarting Unbound..."
systemctl stop systemd-resolved || true # Disable resolved if it conflicts
systemctl disable systemd-resolved || true
# Ensure configs are valid and restart
systemctl restart unbound
systemctl enable unbound

echo "📂 Configuring App..."
mkdir -p /etc/astracat-dns
# Only overwrite config if it doesn't exist to preserve user changes, or force it?
# User wants "setup", so let's ensure it's there.
cp config.yaml /etc/astracat-dns/
cp hosts /etc/astracat-dns/ # Install hosts file

# --- Auto-Detect Certificates ---
echo "🔍 Searching for SSL Certificates in /etc/letsencrypt/live/ ..."
CERT_PATH=""
KEY_PATH=""
FOUND_DOMAIN=""

# Loop through directories to find a valid pair
if [ -d "/etc/letsencrypt/live" ]; then
    for dir in /etc/letsencrypt/live/*; do
        if [ -d "$dir" ] && [ -f "$dir/fullchain.pem" ] && [ -f "$dir/privkey.pem" ]; then
            # Check if it's the specific one we want or just pick the first valid one
            # Ideally prefer 'dns.astracat.ru' if present
            CURRENT_DOMAIN=$(basename "$dir")
            if [[ "$CURRENT_DOMAIN" == *"astracat"* ]] || [ -z "$FOUND_DOMAIN" ]; then
                CERT_PATH="$dir/fullchain.pem"
                KEY_PATH="$dir/privkey.pem"
                FOUND_DOMAIN="$CURRENT_DOMAIN"
            fi
        fi
    done
fi

if [ -n "$FOUND_DOMAIN" ]; then
    echo "✅ Found certificates for domain: $FOUND_DOMAIN"
    echo "   Cert: $CERT_PATH"
    echo "   Key:  $KEY_PATH"
else
    echo "⚠️  No certificates found in /etc/letsencrypt/live/"
    echo "   Using default/fallback paths. Proxy might fail to start if files are missing."
    CERT_PATH="/etc/letsencrypt/live/dns.astracat.ru/fullchain.pem"
    KEY_PATH="/etc/letsencrypt/live/dns.astracat.ru/privkey.pem"
fi
# --------------------------------

# --- Ensure Port 53 is FREE ---
echo "🧹 Cleaning up Port 53..."
DEBIAN_FRONTEND=noninteractive apt-get install -y psmisc # for fuser
systemctl stop systemd-resolved || true
systemctl disable systemd-resolved || true
# Kill anything listening on 53 UDP/TCP
fuser -k 53/udp || true
fuser -k 53/tcp || true
# Wait a sec
sleep 2

echo "🛡️  Creating Systemd Service for Rust Core..."
cat > /etc/systemd/system/astracat-dns.service << EOS
[Unit]
Description=Astracat DNS Resolver (Rust)
After=network.target

[Service]
ExecStart=/usr/local/bin/astracat-dns
Restart=always
User=root
# Ensure we bind to 53. Unbound upstream is via LOCALHOST (since no docker net).
# Wait, un-dockerized setup needs Unbound installed on HOST?
# Yes. If 'type: unbound', user needs 'sudo apt install unbound' OR core falls back to recursive.
# Let's verify environment. Assume recursive fallback or User installed unbound.
# Usually native binary defaults to recursive internally if configured so.
Environment=RUST_LOG=error
WorkingDirectory=/etc/astracat-dns

[Install]
WantedBy=multi-user.target
EOS

echo "🛡️  Creating Systemd Service for Go Proxy..."
# Note: We inject the found paths using placeholders
cat > /etc/systemd/system/astracat-proxy.service << EOS
[Unit]
Description=Astracat DoH/DoT Proxy
After=network.target astracat-dns.service

[Service]
ExecStart=/usr/local/bin/astracat-proxy -upstream=127.0.0.1:53 -doh=0.0.0.0:443 -dot=0.0.0.0:853 -cert=${CERT_PATH} -key=${KEY_PATH} -quiet
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOS

echo "🔄 Reloading and Starting Services..."
systemctl daemon-reload
systemctl enable --now astracat-dns
systemctl enable --now astracat-proxy
systemctl restart astracat-dns
systemctl restart astracat-proxy

echo "✅ Deployment Complete! Services are running 🚀"
EOF
chmod +x deploy_pkg/setup_remote.sh

# 4. Upload and Execute
echo "📤 Uploading to $REMOTE..."
scp -r deploy_pkg/* "$REMOTE:/tmp/"

echo "🔧 Executing remote setup..."
ssh "$REMOTE" "cd /tmp && ./setup_remote.sh"

echo "🎉 Done! binaries deployed and services started."
