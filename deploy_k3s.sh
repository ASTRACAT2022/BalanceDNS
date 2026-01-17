#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting AstracatDNS deployment to K3s...${NC}"

# Check for K3s/Kubectl
if command -v k3s >/dev/null 2>&1; then
    KUBECTL="k3s kubectl"
    CTR="k3s ctr"
elif command -v kubectl >/dev/null 2>&1; then
    KUBECTL="kubectl"
    # If not using k3s command directly, assume standard docker registry or local load might be needed
    # But for this script, we assume k3s environment where we can import images or use local registry.
    CTR=""
else
    echo -e "${RED}Error: neither k3s nor kubectl found.${NC}"
    exit 1
fi

# 1. Build Docker Image
echo -e "${YELLOW}Building Docker image...${NC}"
docker build -t astracat-dns:latest .

# 2. Import Image to K3s (if using k3s command)
if [ ! -z "$CTR" ]; then
    echo -e "${YELLOW}Importing image to K3s...${NC}"
    # Save image to tar and import (most reliable way for k3s without registry)
    docker save astracat-dns:latest > astracat-dns.tar
    $CTR images import astracat-dns.tar
    rm astracat-dns.tar
else
    echo -e "${YELLOW}Skipping direct image import (using standard Docker/Kubectl context). Ensure your cluster can pull 'astracat-dns:latest' (e.g. set imagePullPolicy: Never).${NC}"
fi

# 3. Create ConfigMap from local files
echo -e "${YELLOW}Creating ConfigMap from local config.yaml and hosts...${NC}"
# We use --dry-run=client -o yaml to generate the manifest, then apply it.
# This handles updates cleanly.
$KUBECTL create configmap astracat-config \
    --from-file=config.yaml=config.yaml \
    --from-file=hosts=hosts \
    --dry-run=client -o yaml | $KUBECTL apply -f -

# 4. Handle Certificates (Secrets)
if [ -d "cert" ] && [ -f "cert/fullchain.pem" ] && [ -f "cert/privkey.pem" ]; then
    echo -e "${YELLOW}Found certificates in cert/ directory. Creating Secret...${NC}"
    $KUBECTL create secret generic astracat-certs \
        --from-file=fullchain.pem=cert/fullchain.pem \
        --from-file=privkey.pem=cert/privkey.pem \
        --dry-run=client -o yaml | $KUBECTL apply -f -
else
    echo -e "${YELLOW}No certificates found in cert/. Creating empty secret to prevent mount errors...${NC}"
    # Create a dummy secret if needed, or ensuring the deployment doesn't fail if optional
    # Since deployment mounts it as optional, we might not strictly need it,
    # but having the secret object exist avoids "secret not found" warnings/errors depending on K8s version.
    $KUBECTL create secret generic astracat-certs \
        --from-literal=placeholder=true \
        --dry-run=client -o yaml | $KUBECTL apply -f -
fi

# 5. Apply Manifests
echo -e "${YELLOW}Applying Kubernetes manifests...${NC}"
$KUBECTL apply -f k8s/deployment.yaml
$KUBECTL apply -f k8s/service.yaml

# Force restart to pick up config/image changes
$KUBECTL rollout restart deployment/astracat-dns

# 6. Wait for Rollout
echo -e "${YELLOW}Waiting for deployment rollout...${NC}"
$KUBECTL rollout status deployment/astracat-dns

# 7. Show Info
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "Service Info:"
$KUBECTL get svc astracat-dns
echo -e "\nPod Info:"
$KUBECTL get pods -l app=astracat-dns
