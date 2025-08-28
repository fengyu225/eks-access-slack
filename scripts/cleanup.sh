#!/bin/bash

set -e

echo "Cleaning up eks-access-slack resources..."

# Delete Kind cluster
echo "Deleting Kind cluster..."
kind delete cluster --name eks-access-slack

# Remove Docker image
echo "Removing Docker image..."
docker rmi eks-access-slack:latest 2>/dev/null || true

echo "Cleanup complete!"
