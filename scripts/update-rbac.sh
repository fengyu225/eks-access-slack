#!/bin/bash

# Script to regenerate and deploy RBAC from controller annotations
# This should be run whenever RBAC annotations are updated in controller code

set -e

echo "Regenerating RBAC from controller annotations..."

# Generate manifests from kubebuilder annotations
echo "Running make manifests..."
make manifests

# Generate RBAC for deployment
echo "Generating deployment RBAC..."

# Create the deployment RBAC file with proper naming
cat > deploy/rbac-generated.yaml << 'EOF'
# This file is generated from controller RBAC annotations using make manifests
# Do not edit manually - update RBAC annotations in controller code instead

apiVersion: v1
kind: ServiceAccount
metadata:
  name: eks-access-slack-sa
  namespace: eks-access-slack
---
EOF

# Append the generated ClusterRole with updated metadata
echo "apiVersion: rbac.authorization.k8s.io/v1" >> deploy/rbac-generated.yaml
echo "kind: ClusterRole" >> deploy/rbac-generated.yaml
echo "metadata:" >> deploy/rbac-generated.yaml
echo "  name: eks-access-slack-role" >> deploy/rbac-generated.yaml
sed -n '/^rules:/,$p' controller/config/rbac/role.yaml >> deploy/rbac-generated.yaml

# Append the ClusterRoleBinding
cat >> deploy/rbac-generated.yaml << 'EOF'
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: eks-access-slack-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: eks-access-slack-role
subjects:
- kind: ServiceAccount
  name: eks-access-slack-sa
  namespace: eks-access-slack
EOF

echo "Generated deploy/rbac-generated.yaml"

# Apply the updated RBAC
echo "Applying updated RBAC..."
kubectl apply -f deploy/rbac-generated.yaml

echo "RBAC update complete!"
echo ""
echo "To use the generated RBAC in CI/CD, update your deployment scripts to use:"
echo "   kubectl apply -f deploy/rbac-generated.yaml"
