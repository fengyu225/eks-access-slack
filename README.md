# Temporary Elevated EKS Access

A Kubernetes-native solution for managing temporary EKS cluster access through Slack-based approval workflows. This system provides secure, auditable, and time-limited access to Amazon EKS clusters with multi-stage approval processes.

## Architecture Overview

This system consists of two main components:
- **Controller**: A Kubernetes controller that manages EKS access requests and AWS resources
- **Slack Bot**: A Slack integration that handles user interactions and approval workflows

## Access Request State Transition

The EKS access request follows a state machine to ensure proper approval and resource management:

### State Flow Diagram

```
pending -> awaiting-approval -> approved -> provisioning -> active -> expired/revoked
     |            |                |             |
     v            v                v             v
   failed      rejected         failed        failed
```

### State Descriptions

1. **pending**: Initial state when a request is created. The system evaluates approval policies and determines required approvers.

2. **awaiting-approval**: Request is waiting for approval from designated approvers. Multiple stages may be required based on the approval policy.

3. **approved**: All required approvals have been received. The system is ready to provision AWS resources.

4. **provisioning**: AWS EKS access entry is being created. This involves calling AWS APIs to grant the requested IAM role access to the EKS cluster.

5. **active**: Access is successfully provisioned and the user can access the EKS cluster using their AWS credentials.

6. **expired**: Access has reached its expiration time and AWS resources have been cleaned up.

7. **revoked**: Access was manually terminated before expiration.

8. **rejected**: Request was denied by an approver at any approval stage.

9. **failed**: An error occurred during processing (e.g., AWS API failures, invalid configurations).

### State Transition Rules

- **pending -> awaiting-approval**: Occurs when approval policy requires manual approval
- **pending -> approved**: Occurs when approval policy has `autoApprove: true`
- **awaiting-approval -> approved**: All required approvals received for all stages
- **awaiting-approval -> rejected**: Any approver rejects the request
- **approved -> provisioning**: System begins AWS resource creation
- **provisioning -> active**: AWS EKS access entry successfully created
- **provisioning -> failed**: AWS API errors or configuration issues
- **active -> expired**: Natural expiration based on `expirationTime`
- **active -> revoked**: Manual termination by administrator
- **Any state -> failed**: System errors or invalid configurations

## Slack Integration and User Experience

### Slash Commands

Users can request EKS access directly from Slack using slash commands:

```
/request-eks
```

This opens an interactive modal where users can:
- Select AWS account from available options
- Choose EKS cluster from discovered clusters
- Select desired access policy (View, Edit, Admin, Cluster Admin)
- Select IAM role to assume
- Provide justification for access request

### Approval Workflow

#### For Approvers

1. **Notification**: Approvers receive direct messages with approval requests containing:
   - Requestor information
   - Cluster and access details
   - Justification provided
   - Interactive approve/reject buttons

2. **Decision Process**: Approvers can:
   - Click "Approve" to approve the request
   - Click "Reject" to deny the request
   - View all request details before making a decision

3. **Multi-stage Approval**: For production environments:
   - Stage 1: Team lead approval
   - Stage 2: Platform team approval
   - Each stage can have different approvers and requirements

#### For Requestors

1. **Request Status**: Requestors receive notifications about:
   - Request submission confirmation
   - Approval/rejection decisions
   - Access activation when ready
   - Access termination/expiration

2. **Real-time Updates**: All status changes are communicated via direct messages

### Message Examples

#### Approval Request (to Approver)
```
*Access Request Approval Required*
Requestor: user@company.com
AWS Account: 123456789012
EKS Cluster: prod-cluster-1
Access Policy: AmazonEKSAdminPolicy
IAM Role: arn:aws:iam::123456789012:role/eks-admin-role
Reason: Need to debug production issue with pod scheduling

Stage: 1 (Team Lead Approval)

[Approve] [Reject]
```

#### Access Active (to Requestor)
```
*EKS Access Active*
Your EKS access is now active!
Cluster: prod-cluster-1
Access Policy: AmazonEKSAdminPolicy
Access Entry ARN: arn:aws:eks:us-west-2:123456789012:access-entry/...
You can now access the cluster using your configured AWS credentials.
```

## Local Setup with Kind Cluster

### Prerequisites

- Docker installed and running
- kubectl installed
- Kind installed (`brew install kind` on macOS)
- Go 1.24+ installed
- Make utility

### Quick Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd eks-access-slack
   ```

2. **Create Kind cluster**:
   ```bash
   ./scripts/setup-kind.sh
   ```

   This script will:
   - Create a 3-node Kind cluster with ingress support
   - Build and load the Docker image
   - Generate and apply CRDs
   - Set up namespaces and RBAC

3. **Configure Slack credentials** (optional for testing):
   ```bash
   # Create base64 encoded credentials
   echo -n "your-slack-bot-token" | base64
   echo -n "your-slack-app-token" | base64
   
   # Edit deploy/secret.yaml with your credentials
   kubectl apply -f deploy/secret.yaml
   ```

4. **Deploy the application**:
   ```bash
   kubectl apply -f deploy/deployment.yaml
   kubectl apply -f deploy/service.yaml
   ```

5. **Verify deployment**:
   ```bash
   kubectl get pods -n eks-access-slack
   kubectl logs -f deployment/eks-access-slack -n eks-access-slack
   ```

### Development Workflow

For local development and testing:

```bash
# Build and redeploy
./scripts/rebuild-and-deploy.sh

# View logs
kubectl logs -f deployment/eks-access-slack -n eks-access-slack

# Test with sample resources
kubectl apply -f test-account-cluster.yaml
kubectl apply -f test-approval-policy.yaml
kubectl apply -f test-iam-role.yaml

# Create a test access request
kubectl apply -f - <<EOF
apiVersion: access.eksaccess.io/v1alpha1
kind: EKSAccessRequest
metadata:
  name: test-request
  namespace: eks-access-slack
spec:
  requestor: "test@example.com"
  iamRole: "arn:aws:iam::123456789012:role/test-role"
  awsAccount: "123456789012"
  eksCluster: "test-cluster"
  accessPolicy: "AmazonEKSViewPolicy"
  reason: "Testing the access request system"
  approvalPolicy: "default"
EOF
```

### Cleanup

To clean up the Kind cluster:

```bash
kind delete cluster --name eks-access-slack
```

## Configuration

### Approval Policies

Create approval policies to define access rules:

```yaml
apiVersion: access.eksaccess.io/v1alpha1
kind: ApprovalPolicy
metadata:
  name: production-policy
spec:
  description: "Production access requires two-stage approval"
  autoApprove: false
  maxAccessDuration: "8h"
  conditions:
    accounts: ["123456789012"]
    clusters: ["prod-cluster-1"]
  stages:
    - stageNumber: 1
      name: "Team Lead Approval"
      approvers: ["team-lead@company.com"]
      requiredApprovals: 1
      timeout: "4h"
    - stageNumber: 2
      name: "Platform Team Approval"
      approvers: ["platform-admin@company.com"]
      requiredApprovals: 1
      timeout: "8h"
```

### Environment Variables

- `SLACK_BOT_TOKEN`: Slack bot token for API access
- `SLACK_APP_TOKEN`: Slack app token for Socket Mode
- `K8S_NAMESPACE`: Kubernetes namespace (default: "default")
- `DEFAULT_REGION`: AWS region for EKS operations (default: "ap-northeast-2")
- `CLEANUP_INTERVAL`: Interval for AWS resource cleanup (default: "5m")