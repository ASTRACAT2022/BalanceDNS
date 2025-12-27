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
    echo "   Installing build-essential, pkg-config, libssl-dev, liblmdb-dev, libunbound-dev, unbound..."
    sudo apt-get update -qq
    sudo apt-get install -y build-essential pkg-config libssl-dev liblmdb-dev libunbound-dev unbound -qq
elif command -v yum &> /dev/null; then
    echo "   Installing development tools, openssl-devel, lmdb-devel, unbound-devel, unbound..."
    sudo yum groupinstall -y "Development Tools"
    sudo yum install -y openssl-devel lmdb-devel unbound-devel unbound
else
    echo "⚠️  Warning: Package manager not found or not supported in this script."
    echo "   Please ensure you have dependencies installed."
fi

# Configure Unbound (Local Recursive Resolver)
echo "🌍 Configuring Unbound as local recursive resolver on 127.0.0.1:5353..."
if command -v unbound &> /dev/null; then
    sudo bash -c "cat > /etc/unbound/unbound.conf" <<EOF
server:
    verbosity: 1
    interface: 127.0.0.1@5353
    port: 5353
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: no
    num-threads: 2
    
    # Minimize internal cache (Rust handles caching)
    msg-cache-size: 1m
    rrset-cache-size: 1m
    cache-max-ttl: 0
    infra-cache-numhosts: 100
EOF

    # Restart Unbound
    echo "🔄 Restarting Unbound service..."
    if command -v systemctl &> /dev/null; then
        sudo systemctl enable unbound
        sudo systemctl restart unbound
    fi
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
STALE_CONFIG="/usr/local/etc/astracat-dns/config.yaml"

echo "📜 Installing configuration to $CONFIG_FILE..."
sudo mkdir -p "$CONFIG_DIR"
if [ -f "$PROJECT_DIR/config.yaml" ]; then
    sudo cp "$PROJECT_DIR/config.yaml" "$CONFIG_FILE"
    echo "   Config installed to /etc/astracat-dns/config.yaml."
    
    # Cleanup stale config to prevent confusion (Force remove)
    echo "🧹 Ensuring stale configuration at $STALE_CONFIG is removed..."
    sudo rm -f "$STALE_CONFIG"
    if [ -f "$STALE_CONFIG" ]; then
         echo "⚠️  Failed to remove stale config. Please remove manually."
    fi
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
Environment=RUST_LOG=error

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
