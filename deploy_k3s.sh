#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting AstracatDNS deployment for K3s...${NC}"

# 1. Ensure Certificates Exist
if [ -d "cert" ] && [ -f "cert/privkey.pem" ] && [ -f "cert/fullchain.pem" ]; then
    echo -e "${GREEN}Using existing certificates from cert/ directory.${NC}"
else
    echo "Certificates not found. Generating self-signed certificates for testing..."
    mkdir -p cert
    openssl req -x509 -newkey rsa:4096 -keyout cert/privkey.pem -out cert/fullchain.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
fi

# 2. Build Docker Image (Self-contained)
echo -e "${GREEN}Building Docker image...${NC}"
# Use sudo if docker requires it, but try without first or let user handle permissions
docker build -t astracat-dns:latest .

# 3. Export and Import Image into K3s
echo -e "${GREEN}Importing image into K3s...${NC}"
IMAGE_TAR="astracat-dns.tar"
docker save -o $IMAGE_TAR astracat-dns:latest
sudo k3s ctr images import $IMAGE_TAR
rm $IMAGE_TAR

echo -e "${GREEN}NOTE: Image imported to local K3s node only. For multi-node clusters, ensure image distribution.${NC}"

# 4. Deploy to Kubernetes
echo -e "${GREEN}Applying Kubernetes manifests...${NC}"
sudo kubectl apply -f kubernetes/deployment.yaml

# 5. Restart Deployment to pick up new image
echo -e "${GREEN}Restarting deployment...${NC}"
sudo kubectl rollout restart deployment/astracat-dns

echo -e "${GREEN}Deployment complete!${NC}"
echo "Check status with: sudo kubectl get pods -l app=astracat-dns"
