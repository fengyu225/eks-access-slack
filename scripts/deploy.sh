#!/bin/bash

set -e

echo "Deploying eks-access-slack application..."

# Check if namespace exists
if ! kubectl get namespace eks-access-slack &> /dev/null; then
    echo "Namespace 'eks-access-slack' not found. Please run setup-kind.sh first."
    exit 1
fi

# Check if secrets exist
if ! kubectl get secret eks-access-slack-secrets -n eks-access-slack &> /dev/null; then
    echo "Secrets not found. Please run update-secrets.sh first."
    exit 1
fi

# Apply deployment
echo "Deploying application..."
kubectl apply -f deploy/deployment.yaml

# Apply service
echo "Creating service..."
kubectl apply -f deploy/service.yaml

# Wait for deployment to be ready
echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/eks-access-slack -n eks-access-slack

echo "Deployment complete!"
echo ""
echo "Check the deployment:"
echo "   kubectl get pods -n eks-access-slack"
echo "   kubectl get services -n eks-access-slack"
echo ""
echo "View logs:"
echo "   kubectl logs -f deployment/eks-access-slack -n eks-access-slack"
echo ""
echo "Port forward to access the application:"
echo "   kubectl port-forward service/eks-access-slack-service 8080:8080 -n eks-access-slack"
echo "   kubectl port-forward service/eks-access-slack-service 8081:8081 -n eks-access-slack"
echo "   kubectl port-forward service/eks-access-slack-service 8082:8082 -n eks-access-slack"
