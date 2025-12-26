#!/bin/bash
set -e

# Script Directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
SERVICE_NAME="astracat-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_PATH="/usr/local/bin/${SERVICE_NAME}"
BUILD_TARGET_DIR="$PROJECT_DIR/target/release"

echo "🚀 Starting installation of Astracat DNS Resolver (Rust Edition)..."

# 1. Check for Rust/Cargo
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo (Rust) is not installed. Please install Rust first: https://rustup.rs/"
    exit 1
fi

echo "📁 Project directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

# 2. Install dependencies (Linux/Debian focused)
echo "🔧 Checking system dependencies..."
if command -v apt-get &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    echo "   Installing build-essential, pkg-config, libssl-dev, liblmdb-dev, libunbound-dev..."
    sudo apt-get update -qq
    sudo apt-get install -y build-essential pkg-config libssl-dev liblmdb-dev libunbound-dev -qq
elif command -v yum &> /dev/null; then
    echo "   Installing development tools, openssl-devel, lmdb-devel, unbound-devel..."
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y openssl-devel lmdb-devel unbound-devel
else
    echo "⚠️  Warning: Package manager not found or not supported in this script."
    echo "   Please ensure you have build-essential, libssl-dev, and liblmdb-dev (or equivalent) installed."
fi

# 3. Build project
echo "🔨 Building project with Cargo (Release mode)..."
cargo build --release

# 4. Verify binary exists
COMPILED_BINARY="$BUILD_TARGET_DIR/astracat-dns-rs" # Binary name from Cargo.toml is astracat-dns-rs
if [ ! -f "$COMPILED_BINARY" ]; then
    echo "❌ Build failed or binary not found at $COMPILED_BINARY"
    exit 1
fi

echo "✅ Build successful."

# 5. Install binary
echo "🛑 Stopping existing service to allow update..."
if command -v systemctl &> /dev/null; then
    sudo systemctl stop "$SERVICE_NAME" || true
elif [[ "$OSTYPE" == "darwin"* ]]; then
     sudo launchctl unload "/Library/LaunchDaemons/com.astracat.dns-resolver.plist" 2>/dev/null || true
fi

echo "📦 Installing binary to $BINARY_PATH..."
sudo cp "$COMPILED_BINARY" "$BINARY_PATH"
sudo chmod +x "$BINARY_PATH"

# 5.1 Install Config
CONFIG_DIR="/etc/astracat-dns"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
echo "📜 Installing configuration to $CONFIG_FILE..."
sudo mkdir -p "$CONFIG_DIR"
if [ -f "$PROJECT_DIR/config.yaml" ]; then
    sudo cp "$PROJECT_DIR/config.yaml" "$CONFIG_FILE"
    echo "   Config installed."
else
    echo "⚠️  config.yaml not found in project root. Skipping config installation."
fi

# 6. Create Service
echo "📝 Configuring service..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    PLIST_SOURCE="$PROJECT_DIR/com.astracat.dns-resolver.plist"
    PLIST_DEST="/Library/LaunchDaemons/com.astracat.dns-resolver.plist"
    
    echo "🍎 macOS detected. Installing Launchd plist..."
    
    # Update WorkingDirectory in plist to match current project dir (dynamic update)
    # We use sed to replace the placeholder or just rely on what we wrote if it matches, 
    # but let's ensure it's correct in the source file first.
    # Actually, let's just write the file here dynamically to be safe about the path.
    
    sudo bash -c "cat > $PLIST_DEST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.astracat.dns-resolver</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BINARY_PATH</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$PROJECT_DIR</string>
    <key>StandardOutPath</key>
    <string>/tmp/astracat-dns.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/astracat-dns.error.log</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
    
    echo "🔄 Loading Launchd service..."
    sudo launchctl unload "$PLIST_DEST" 2>/dev/null || true
    sudo launchctl load -w "$PLIST_DEST"
    echo "✅ Service loaded via launchctl!"

else
    # Linux / Systemd
    echo "🐧 Linux detected. Installing Systemd service..."
    sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Astracat DNS Resolver Service (Rust)
After=network.target

[Service]
ExecStart=$BINARY_PATH
WorkingDirectory=$PROJECT_DIR
Restart=always
User=root
StandardOutput=journal
StandardError=journal
Environment=RUST_LOG=info,hickory_server=debug,h2=info,rustls=info

[Install]
WantedBy=multi-user.target
EOF

    echo "🔄 Reloading systemd daemon and starting service..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl daemon-reload
        sudo systemctl enable "$SERVICE_NAME"
        sudo systemctl restart "$SERVICE_NAME"
        echo "✅ Service started!"
    else
        echo "⚠️  'systemctl' not available. Service installed but not started automatically."
        echo "   You can run the binary manually: sudo $BINARY_PATH"
    fi
fi

echo "🎉 Installation complete!"
