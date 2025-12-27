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

# Check for cross
if ! command -v cross &> /dev/null; then
    echo "❌ 'cross' is not installed. To build Linux binaries on Mac, we need it."
    echo "👉 Please run: cargo install cross"
    echo "   (Note: cross requires Docker Desktop to be running in the background to handle the toolchain)"
    read -p "Attempt to install cross now? [y/N] " confirm
    if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
        cargo install cross
    else
        echo "Please install cross or build on a Linux machine."
        exit 1
    fi
fi

cross build --release --target x86_64-unknown-linux-gnu


# 2. Build Go Proxy (Linux x86_64)
echo "🐭 Building Go Proxy for Linux x86_64..."
cd go-proxy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o astracat-proxy main.go
cd ..

# 3. Prepare Deployment Package
echo "📦 Packaging..."
mkdir -p deploy_pkg
# Default cross output
cp target/x86_64-unknown-linux-gnu/release/astracat-dns-rs deploy_pkg/astracat-dns

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
