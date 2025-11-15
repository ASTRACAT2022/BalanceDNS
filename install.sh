#!/bin/bash

# Update package lists
sudo apt-get update

# Install unbound and unbound-anchor
sudo apt-get install -y unbound unbound-anchor

# Create unbound directory if it doesn't exist
sudo mkdir -p /etc/unbound

# Generate root.key
sudo unbound-anchor -a /etc/unbound/root.key

# Build the application
go build .
