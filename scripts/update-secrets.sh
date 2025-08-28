#!/bin/bash

set -e

echo "Updating Kubernetes secrets with your credentials..."

# Check if required environment variables are set
if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ] || [ -z "$AWS_SESSION_TOKEN" ]; then
    echo "AWS credentials not found in environment variables."
    echo "Please set the following environment variables:"
    echo "   export AWS_ACCESS_KEY_ID=your_access_key_id"
    echo "   export AWS_SECRET_ACCESS_KEY=your_secret_access_key"
    echo "   export AWS_SESSION_TOKEN=your_session_token"
    exit 1
fi

if [ -z "$SLACK_BOT_TOKEN" ] || [ -z "$SLACK_APP_TOKEN" ]; then
    echo "Slack tokens not found in environment variables."
    echo "Please set the following environment variables:"
    echo "   export SLACK_BOT_TOKEN=xoxb-your-bot-token"
    echo "   export SLACK_APP_TOKEN=xapp-your-app-token"
    exit 1
fi

# Create a temporary secret file
cat > /tmp/eks-access-slack-secrets.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: eks-access-slack-secrets
  namespace: eks-access-slack
type: Opaque
data:
  AWS_ACCESS_KEY_ID: $(echo -n "$AWS_ACCESS_KEY_ID" | base64)
  AWS_SECRET_ACCESS_KEY: $(echo -n "$AWS_SECRET_ACCESS_KEY" | base64)
  AWS_SESSION_TOKEN: $(echo -n "$AWS_SESSION_TOKEN" | base64)
  SLACK_BOT_TOKEN: $(echo -n "$SLACK_BOT_TOKEN" | base64)
  SLACK_APP_TOKEN: $(echo -n "$SLACK_APP_TOKEN" | base64)
EOF

# Apply the secret
echo "Applying secrets to Kubernetes..."
kubectl apply -f /tmp/eks-access-slack-secrets.yaml

# Clean up
rm /tmp/eks-access-slack-secrets.yaml

echo "Secrets updated successfully!"
echo ""
echo "You can now deploy the application:"
echo "   kubectl apply -f deploy/deployment.yaml"
echo "   kubectl apply -f deploy/service.yaml"
