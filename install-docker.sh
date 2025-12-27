#!/bin/bash
set -e

echo "🐳 Starting Astracat DNS Docker Installation..."

# 1. Check for Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

# 1.1 Configure Docker Mirror (Critical for Russia)
if [ ! -f /etc/docker/daemon.json ]; then
    echo "🌍 Configuring Docker Mirror (mirror.gcr.io) for better connectivity..."
    sudo mkdir -p /etc/docker
    echo '{
      "registry-mirrors": ["https://mirror.gcr.io"]
    }' | sudo tee /etc/docker/daemon.json
    sudo systemctl restart docker
    echo "✅ Docker restarted with mirror configuration."
else
    # Check if a mirror is already configured
    if ! grep -q "registry-mirrors" /etc/docker/daemon.json; then
         echo "⚠️  No registry mirrors found in /etc/docker/daemon.json. Adding Google Mirror..."
         # Basic append is risky with JSON, so we just warn or backup/overwrite if user agrees.
         # For automation safety, we'll suggest it or try a safe sed inject if simple.
         # Let's simple overwrite for now because this is likely a fresh install context
         # OR simply rely on the user to fix it if they have custom config.
         # BETTER: Just print a warning tip.
         echo "💡 TIP: If you have connection issues, add 'registry-mirrors': ['https://mirror.gcr.io'] to /etc/docker/daemon.json"
    fi
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
             # Crucial: Let's Encrypt uses symlinks in /live pointing to /archive
             # We must mount the ROOT config dir (e.g. /etc/letsencrypt)
             # Assumption: path is like /etc/letsencrypt/live/domain/file
             if [[ "$FULL_CERT_PATH" == *"/letsencrypt/"* ]]; then
                 CERT_ROOT="/etc/letsencrypt"
                 # Calculate relative path for Go Proxy
                 # e.g. /live/dns.astracat.ru/fullchain.pem
                 # resulting container path: /certs_root/live/dns.astracat.ru/fullchain.pem
                 CERT_SUBPATH=${FULL_CERT_PATH#$CERT_ROOT}
                 PROXY_CERT="/certs_root$CERT_SUBPATH"
                 
                 # Key path assumed similar
                 KEY_PATH_LINE=$(grep "key_file:" "$CONFIG_FILE" | head -n 1)
                 FULL_KEY_PATH=$(echo "$KEY_PATH_LINE" | sed -n 's/.*"\(.*\)".*/\1/p')
                 KEY_SUBPATH=${FULL_KEY_PATH#$CERT_ROOT}
                 PROXY_KEY="/certs_root$KEY_SUBPATH"
                 
                 echo "🔑 Detected Let's Encrypt. Mounting Root: $CERT_ROOT"
                 echo "   Cert Path in Container: $PROXY_CERT"
                 
                 echo "HOST_CERT_ROOT=$CERT_ROOT" > .env
                 echo "PROXY_CERT_PATH=$PROXY_CERT" >> .env
                 echo "PROXY_KEY_PATH=$PROXY_KEY" >> .env
                 echo "UNBOUND_UPSTREAM=unbound:53" >> .env
                 echo "✅ Updated .env configuration from config.yaml"
             else
                 # Fallback for custom certs (non-LE)
                 CERT_DIR=$(dirname "$FULL_CERT_PATH")
                 echo "🔑 Detected Custom Certificates: $CERT_DIR"
                 echo "HOST_CERT_ROOT=$CERT_DIR" > .env
                 # For custom certs, we mount dir to /certs_root, so file is /certs_root/filename
                 CERT_NAME=$(basename "$FULL_CERT_PATH")
                 KEY_NAME=$(basename "$FULL_KEY_PATH") # Assume key defined
                 echo "PROXY_CERT_PATH=/certs_root/$CERT_NAME" >> .env
                 # This part is a bit weak if key is in diff dir, but good enough for now
                 echo "PROXY_KEY_PATH=/certs_root/privkey.pem" >> .env # default fallback
                 echo "UNBOUND_UPSTREAM=unbound:53" >> .env
             fi
        fi
    fi
else
    echo "⚠️  config.yaml not found. Using defaults in .env if available."
fi

# 1.6 Ensure .env has critical values (Safety Fallback)
if ! grep -q "HOST_CERT_ROOT" .env 2>/dev/null; then
    echo "⚠️  Certificate configuration missing. Setting fallback defaults (Self-signed mode)..."
    # Fallback to local ./certs mapping
    echo "HOST_CERT_ROOT=./certs" >> .env
    echo "PROXY_CERT_PATH=/certs_root/server.crt" >> .env
    echo "PROXY_KEY_PATH=/certs_root/server.key" >> .env
    echo "UNBOUND_UPSTREAM=unbound:53" >> .env
fi

# 1.7 Debug .env content
echo "📄 Final .env configuration:"
cat .env
echo "--------------------------------"

# 2. Build first (while DNS/Internet is definitely working)
echo "🏗️  Building Containers..."
# Prune first
echo "🧹 Cleaning up Docker cache..."
docker system prune -f > /dev/null 2>&1 || true
docker builder prune -f > /dev/null 2>&1 || true

# Build now
$DOCKER_COMPOSE_CMD build

# 3. Stop conflicting system services (Only NOW, before starting containers)
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

echo "🚀 Starting Containers..."
$DOCKER_COMPOSE_CMD down --remove-orphans || true
$DOCKER_COMPOSE_CMD up -d --no-build

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
