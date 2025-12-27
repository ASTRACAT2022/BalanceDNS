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

# Use explicit Docker build to ensure compatibility and avoid 'cross' toolchain issues
if ! command -v docker &> /dev/null; then
    echo "❌ Docker Desktop is required for the *build* step (to compile Linux binary on Mac)."
    exit 1
fi

# Build using official Rust docker image
# We mount the cache to speed it up
docker run --rm \
    -v "$(pwd)":/usr/src/app \
    -w /usr/src/app \
    -e CARGO_HOME=/usr/src/app/.cargo-cache \
    rust:1.83-bullseye \
    cargo build --release --jobs 4

# Check artifacts
if [ ! -f target/release/astracat-dns-rs ]; then
    echo "❌ Build failed. Binary not found in target/release/astracat-dns-rs"
    exit 1
fi


# 2. Build Go Proxy (Linux x86_64)
echo "🐭 Building Go Proxy for Linux x86_64..."
cd go-proxy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o astracat-proxy main.go
cd ..

# 3. Prepare Deployment Package
echo "📦 Packaging..."
mkdir -p deploy_pkg
# Default output
cp target/release/astracat-dns-rs deploy_pkg/astracat-dns

cp go-proxy/astracat-proxy deploy_pkg/
cp config.yaml deploy_pkg/
# We need a simplified install script for the server side
cat > deploy_pkg/setup_remote.sh << 'EOF'
#!/bin/bash
set -e
echo "🔧 Installing binaries..."
mv astracat-dns /usr/local/bin/
mv astracat-proxy /usr/local/bin/
chmod +x /usr/local/bin/astracat-dns /usr/local/bin/astracat-proxy

echo "📂 Configuring..."
mkdir -p /etc/astracat-dns
cp config.yaml /etc/astracat-dns/

echo "🛡️  Creating Systemd Service for Rust Core..."
cat > /etc/systemd/system/astracat-dns.service << EOS
[Unit]
Description=Astracat DNS Resolver (Rust)
After=network.target

[Service]
ExecStart=/usr/local/bin/astracat-dns
Restart=always
User=root
Environment=RUST_LOG=info
WorkingDirectory=/etc/astracat-dns

[Install]
WantedBy=multi-user.target
EOS

echo "🛡️  Creating Systemd Service for Go Proxy..."
cat > /etc/systemd/system/astracat-proxy.service << EOS
[Unit]
Description=Astracat DoH/DoT Proxy
After=network.target astracat-dns.service

[Service]
ExecStart=/usr/local/bin/astracat-proxy -upstream=127.0.0.1:53 -doh=0.0.0.0:443 -dot=0.0.0.0:853 -cert=/etc/letsencrypt/live/dns.astracat.ru/fullchain.pem -key=/etc/letsencrypt/live/dns.astracat.ru/privkey.pem
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

echo "✅ Deployment Complete!"
EOF
chmod +x deploy_pkg/setup_remote.sh

# 4. Upload and Execute
echo "📤 Uploading to $REMOTE..."
scp -r deploy_pkg/* "$REMOTE:/tmp/"

echo "🔧 Executing remote setup..."
ssh "$REMOTE" "cd /tmp && ./setup_remote.sh"

echo "🎉 Done! binaries deployed and services started."
