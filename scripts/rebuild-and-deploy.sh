#!/bin/bash

set -e

echo "Rebuilding and redeploying eks-access-slack..."

# Check if Kind cluster exists
if ! kind get clusters | grep -q eks-access-slack; then
    echo "Kind cluster 'eks-access-slack' not found. Please run setup-kind.sh first."
    exit 1
fi

# Build Docker image
echo "Building Docker image..."
make docker-build

# Load image into Kind cluster
echo "Loading image into Kind cluster..."
kind load docker-image eks-access-slack:latest --name eks-access-slack

# Delete existing deployment
echo "Deleting existing deployment..."
kubectl delete deployment eks-access-slack -n eks-access-slack --ignore-not-found=true

# Wait for deployment to be deleted
echo "Waiting for deployment to be deleted..."
kubectl wait --for=delete deployment/eks-access-slack -n eks-access-slack --timeout=60s 2>/dev/null || true

# Apply deployment
echo "Deploying updated application..."
kubectl apply -f deploy/deployment.yaml

# Wait for deployment to be ready
echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/eks-access-slack -n eks-access-slack

echo "Rebuild and redeploy complete!"
echo ""
echo "Check the deployment:"
echo "   kubectl get pods -n eks-access-slack"
echo ""
echo "View logs:"
echo "   kubectl logs -f deployment/eks-access-slack -n eks-access-slack"
