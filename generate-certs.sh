#!/bin/bash

# Create a self-signed certificate for testing DoH/DoT
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
