#!/bin/bash
set -e

echo "🐳 Starting Astracat DNS Docker Installation..."

# 1. Check for Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first: https://docs.docker.com/engine/install/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
     # Try 'docker compose' plugin
     if ! docker compose version &> /dev/null; then
         echo "❌ docker-compose not found. Please install it."
         exit 1
     fi
     DOCKER_COMPOSE_CMD="docker compose"
else
     DOCKER_COMPOSE_CMD="docker-compose"
fi

echo "✅ Docker detected. Using command: $DOCKER_COMPOSE_CMD"

# 1.5 Parse config.yaml to extract certificate path
# We want to use the certification path defined in config.yaml for the Docker volume
CONFIG_FILE="config.yaml"
if [ -f "$CONFIG_FILE" ]; then
    echo "📖 Reading configuration from $CONFIG_FILE..."
    # Extract cert_file path. simple grep/awk assuming standard formatting
    # Matches: cert_file: "/path/to/cert"
    CERT_PATH_LINE=$(grep "cert_file:" "$CONFIG_FILE" | head -n 1)
    if [ -n "$CERT_PATH_LINE" ]; then
        # Extract path inside quotes
        FULL_CERT_PATH=$(echo "$CERT_PATH_LINE" | sed -n 's/.*"\(.*\)".*/\1/p')
        if [ -n "$FULL_CERT_PATH" ]; then
             CERT_DIR=$(dirname "$FULL_CERT_PATH")
             echo "🔑 Detected Certificate Directory: $CERT_DIR"
             
             # Write to .env
             echo "HOST_CERT_PATH=$CERT_DIR" > .env
             echo "UNBOUND_UPSTREAM=unbound:53" >> .env
             echo "✅ Updated .env configuration from config.yaml"
        fi
    fi
else
    echo "⚠️  config.yaml not found. Using defaults in .env if available."
fi

# 2. Stop conflicting system services
if systemctl is-active --quiet astracat-dns; then
    echo "🛑 Stopping local astracat-dns systemd service to free port 53..."
    sudo systemctl stop astracat-dns
    sudo systemctl disable astracat-dns
fi

if systemctl is-active --quiet unbound; then
    echo "🛑 Stopping local unbound systemd service to free port 5353..."
    sudo systemctl stop unbound
    sudo systemctl disable unbound
fi

# 3. Pull and Build
echo "🏗️  Building and Starting Containers..."
$DOCKER_COMPOSE_CMD down --remove-orphans || true
$DOCKER_COMPOSE_CMD up -d --build

echo "⏳ Waiting for services to initialize..."
sleep 5

# 4. Check status
if $DOCKER_COMPOSE_CMD ps | grep -q "Up"; then
    echo "🎉 Docker Installation Complete!"
    echo "   - Unbound: Recursive Resolver"
    echo "   - Astracat Core: Rust Logic + Cache"
    echo "   - Go Proxy: DoH/DoT Frontend"
    echo ""
    echo "📜 Logs:"
    $DOCKER_COMPOSE_CMD logs --tail=20
else
    echo "❌ Something went wrong. Check logs with: $DOCKER_COMPOSE_CMD logs"
    exit 1
fi
