#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== AstracatDNS K3s/K8s Deployment Script ===${NC}"

# Check for kubectl
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl is not installed or not in PATH.${NC}"
    exit 1
fi

# Check for docker
if command -v docker &> /dev/null; then
    echo -e "${GREEN}[1/2] Building Docker Image...${NC}"
    # In k3s, if using the local container runtime (ctr), you might need to import the image.
    # This script assumes a standard workflow where you build locally.
    # If using k3s with containerd locally, you might need 'k3s ctr images import'.

    docker build -t astracat-dns:latest .

    # Optional: If running k3s locally, try to import the image
    if command -v k3s &> /dev/null; then
        echo -e "${YELLOW}Detecting K3s... Importing image to K3s containerd...${NC}"
        docker save astracat-dns:latest | sudo k3s ctr images import -
    fi
else
    echo -e "${YELLOW}Warning: Docker not found. Skipping build step. Assuming image 'astracat-dns:latest' exists in cluster or registry.${NC}"
fi

echo -e "${GREEN}[2/2] Applying Kubernetes Manifests...${NC}"
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

echo -e "${GREEN}=== Deployment applied! ===${NC}"
echo "Check status with: kubectl get pods -l app=astracat-dns"
echo "Check service IP:  kubectl get svc astracat-dns"
