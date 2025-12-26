#!/bin/bash

BINARY_PATH="/usr/local/bin/astracat-dns"
SERVICE_NAME="astracat-dns"
DNS_PORT="53" # Default config port
TEST_DOMAIN="google.com"

echo "🔍 Verifying Astracat DNS Resolver Migration..."

# 1. Check Binary
if [ -f "$BINARY_PATH" ]; then
    echo "✅ Binary found at $BINARY_PATH"
else
    echo "❌ Binary NOT found at $BINARY_PATH. Did install.sh run successfully?"
fi

# 2. Check Service Status
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Checking Launchd status..."
    if sudo launchctl list | grep -q "com.astracat.dns-resolver"; then
        echo "✅ Service is LOADED in launchd"
    else
        echo "⚠️  Service is NOT loaded in launchd"
    fi
elif command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "✅ Service is ACTIVE"
    else
        echo "⚠️  Service is NOT active. Status:"
        systemctl status "$SERVICE_NAME" --no-pager | head -n 5
    fi
else
    echo "ℹ️  Skipping service status check (no systemctl/launchd)."
fi

# 3. Functional Test
echo "🧪 Running DNS Query test against 127.0.0.1:$DNS_PORT..."
if command -v dig &> /dev/null; then
    RESULT=$(dig @127.0.0.1 -p $DNS_PORT $TEST_DOMAIN +short 2>/dev/null)
    if [ -n "$RESULT" ]; then
        echo "✅ DNS Query Successful! Resolution: $RESULT"
    else
        echo "⚠️  DNS Query failed or timed out. (Is the service running and listening on port $DNS_PORT?)"
    fi
else
    echo "⚠️  'dig' command not found. Skipping functional test."
fi
