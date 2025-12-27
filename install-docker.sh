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
