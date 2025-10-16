#!/bin/bash
set -e

# Получаем абсолютный путь к директории скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
SERVICE_NAME="astracat-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_PATH="$PROJECT_DIR/$SERVICE_NAME"

echo "🚀 Starting installation of Astracat DNS Resolver..."

# Проверка наличия Go
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

echo "📁 Project directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

echo "🔧 Installing required dependencies (libunbound-dev, unbound-anchor)..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y libunbound-dev unbound-anchor
else
    echo "⚠️  Warning: 'apt-get' not found. Please install 'libunbound-dev' and 'unbound-anchor' manually."
fi

echo "🔑 Generating DNSSEC root key..."
sudo mkdir -p /etc/unbound
sudo unbound-anchor -a /etc/unbound/root.key

echo "🔨 Building the project (preferring recursive Unbound backend)..."
# Try to build with Unbound recursive backend first; fall back to stub forwarder if unavailable
if CGO_ENABLED=1 go build -tags=unbound -o "$SERVICE_NAME" .; then
    echo "✅ Built with Unbound recursive backend (CGO enabled)."
else
    echo "⚠️  Falling back to cgo-free stub (forwarder) backend build."
    go build -o "$SERVICE_NAME" .
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Build failed: binary not found at $BINARY_PATH"
    exit 1
fi

echo "✅ Build successful: $BINARY_PATH"

echo "📝 Creating systemd service file: $SERVICE_FILE..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Astracat DNS Resolver Service
After=network.target

[Service]
ExecStart=$BINARY_PATH
WorkingDirectory=$PROJECT_DIR
Restart=always
User=root
StandardOutput=null
StandardError=null
LogLevelMax=0

[Install]
WantedBy=multi-user.target
EOF

echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

echo "🔌 Enabling and starting the $SERVICE_NAME service..."
systemctl enable "$SERVICE_NAME" --now

echo "🎉 Installation complete! The $SERVICE_NAME service is now running."
echo "✅ Systemd logs are disabled for this service."
