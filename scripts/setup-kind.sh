#!/bin/bash

set -e

echo "Setting up Kind cluster for eks-access-slack..."

# Check if Kind is installed
if ! command -v kind &> /dev/null; then
    echo "Kind is not installed. Please install Kind first:"
    echo "   brew install kind  # macOS"
    echo "   or visit: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "Docker is not running. Please start Docker first."
    exit 1
fi

# Create Kind cluster
echo "Creating Kind cluster..."
kind create cluster --name eks-access-slack --config kind-config.yaml

# Wait for cluster to be ready
echo "Waiting for cluster to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=300s

# Build and load the Docker image
echo "Building Docker image..."
make docker-build

echo "Loading image into Kind cluster..."
kind load docker-image eks-access-slack:latest --name eks-access-slack

# Generate CRDs
echo "Generating CRDs..."
make manifests

# Apply namespace
echo "Creating namespace..."
kubectl apply -f deploy/namespace.yaml

# Apply CRDs
echo "Applying CRDs..."
kubectl apply -f controller/config/crd/bases/

# Apply RBAC
echo "Applying RBAC..."
kubectl apply -f deploy/rbac.yaml

# Apply ConfigMap
echo "Applying ConfigMap..."
kubectl apply -f deploy/configmap.yaml

echo "Kind cluster setup complete!"
echo ""
echo "Next steps:"
echo "1. Update deploy/secret.yaml with your actual credentials (base64 encoded)"
echo "2. Run: kubectl apply -f deploy/secret.yaml"
echo "3. Run: kubectl apply -f deploy/deployment.yaml"
echo "4. Run: kubectl apply -f deploy/service.yaml"
echo ""
echo "To check the deployment:"
echo "   kubectl get pods -n eks-access-slack"
echo "   kubectl logs -f deployment/eks-access-slack -n eks-access-slack"
