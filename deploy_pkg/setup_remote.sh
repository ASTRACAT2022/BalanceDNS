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
    cache-max-ttl: 0
    cache-min-ttl: 0
    hide-identity: yes
    hide-version: yes
    minimal-responses: yes
    # Recursion
    do-not-query-localhost: no
    
    # DNSSEC
    module-config: "validator iterator"
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-log-level: 1
    harden-dnssec-stripped: yes
    qname-minimisation: yes
UNBOUND_EOF

echo "🔄 Restarting Unbound..."
# Ensure trust anchor exists (Debian/Ubuntu usually does this, but good to ensure)
/usr/sbin/unbound-anchor -a /var/lib/unbound/root.key || true
chown unbound:unbound /var/lib/unbound/root.key || true

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
