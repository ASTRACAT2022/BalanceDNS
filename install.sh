#!/bin/bash

# Build the DNS server
go build -o /usr/local/bin/dns-resolver cmd/main.go

# Create systemd service file
cat << EOF | sudo tee /etc/systemd/system/dns-resolver.service
[Unit]
Description=DNS Resolver Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dns-resolver
Restart=always
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
sudo chmod +x /usr/local/bin/dns-resolver

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable dns-resolver
sudo systemctl start dns-resolver

echo "DNS Resolver installed and started successfully"
echo "Check status with: systemctl status dns-resolver"