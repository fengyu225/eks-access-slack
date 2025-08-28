package k8sclient

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	"regexp"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	accessv1alpha1 "eks-access-slack/controller/api/v1alpha1"
)

const (
	annotationApprovalPolicy = "eksaccess.io/approval-policy"
)

type K8sClient struct {
	client    client.Client
	namespace string
}

func NewK8sClient(namespace string) (*K8sClient, error) {
	cfg, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := accessv1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add scheme: %w", err)
	}

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return &K8sClient{
		client:    k8sClient,
		namespace: namespace,
	}, nil
}

// CreateAccessRequest creates a new EKS access request
func (c *K8sClient) CreateAccessRequest(ctx context.Context, req *AccessRequestInput) (*accessv1alpha1.EKSAccessRequest, error) {
	var expirationTime *metav1.Time
	if req.Duration != "" {
		duration, err := time.ParseDuration(req.Duration)
		if err != nil {
			return nil, fmt.Errorf("invalid duration: %w", err)
		}
		expTime := metav1.NewTime(time.Now().Add(duration))
		expirationTime = &expTime
	}

	accessRequest := &accessv1alpha1.EKSAccessRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "eks-access-",
			Namespace:    c.namespace,
			Labels: map[string]string{
				"requested-by": sanitizeLabel(req.RequestorEmail),
				"cluster":      sanitizeLabel(req.Cluster),
			},
			Annotations: map[string]string{
				"eksaccess.io/slack-user-id":    req.SlackUserID,
				"eksaccess.io/slack-channel-id": req.SlackChannelID,
			},
		},
		Spec: accessv1alpha1.EKSAccessRequestSpec{
			Requestor:      req.RequestorEmail,
			IAMRole:        req.IAMRole,
			AWSAccount:     req.AWSAccount,
			EKSCluster:     req.Cluster,
			AccessPolicy:   req.AccessPolicy,
			Reason:         req.Reason,
			ExpirationTime: expirationTime,
		},
	}

	if err := c.client.Create(ctx, accessRequest); err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}

	return accessRequest, nil
}

func (c *K8sClient) ApproveRequest(ctx context.Context, requestName, approverEmail, comment string) error {
	var lastErr error
	for i := 0; i < 3; i++ {
		// Get fresh copy of the request
		request := &accessv1alpha1.EKSAccessRequest{}
		if err := c.client.Get(ctx, types.NamespacedName{
			Name:      requestName,
			Namespace: c.namespace,
		}, request); err != nil {
			return fmt.Errorf("failed to get request: %w", err)
		}

		// Validate approver email
		if approverEmail == "" {
			return fmt.Errorf("approver email cannot be empty")
		}

		// Fix stage numbering
		correctStage := request.Status.CurrentStage
		if correctStage == 0 {
			correctStage = 1
			request.Status.CurrentStage = 1
		}

		// CHECK FOR DUPLICATE: See if this approver already approved this stage
		for _, existingApproval := range request.Status.Approvals {
			if existingApproval.Stage == correctStage &&
				existingApproval.Approver == approverEmail &&
				existingApproval.Decision == "approved" {
				// Already approved by this user, skip
				logrus.Infof("User %s already approved stage %d, skipping duplicate", approverEmail, correctStage)
				return nil
			}
		}

		// Create approval record
		approval := accessv1alpha1.Approval{
			Stage:     correctStage,
			Approver:  approverEmail,
			Decision:  "approved",
			Timestamp: metav1.Now(),
			Comment:   comment,
		}

		// Add approval to the list
		request.Status.Approvals = append(request.Status.Approvals, approval)

		// Update status with the approval
		if err := c.client.Status().Update(ctx, request); err != nil {
			lastErr = err
			if errors.IsConflict(err) && i < 2 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to update request status: %w", err)
		}

		// Get fresh copy again for annotation update
		if err := c.client.Get(ctx, types.NamespacedName{
			Name:      requestName,
			Namespace: c.namespace,
		}, request); err != nil {
			return fmt.Errorf("failed to get request for annotation update: %w", err)
		}

		// Force reconciliation by updating an annotation
		if request.Annotations == nil {
			request.Annotations = make(map[string]string)
		}

		request.Annotations["eksaccess.io/last-approval"] = metav1.Now().Format(time.RFC3339)
		request.Annotations["eksaccess.io/last-approval-by"] = approverEmail

		if err := c.client.Update(ctx, request); err != nil {
			lastErr = err
			if errors.IsConflict(err) && i < 2 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if errors.IsConflict(err) {
				return nil
			}
			return fmt.Errorf("failed to trigger reconciliation: %w", err)
		}

		return nil
	}

	if lastErr != nil && errors.IsConflict(lastErr) {
		return nil
	}

	return fmt.Errorf("failed after retries: %w", lastErr)
}

func (c *K8sClient) RejectRequest(ctx context.Context, requestName, approverEmail, reason string) error {
	// Use retry logic for handling conflicts
	var lastErr error
	for i := 0; i < 3; i++ {
		// Get fresh copy of the request
		request := &accessv1alpha1.EKSAccessRequest{}
		if err := c.client.Get(ctx, types.NamespacedName{
			Name:      requestName,
			Namespace: c.namespace,
		}, request); err != nil {
			return fmt.Errorf("failed to get request: %w", err)
		}

		// Validate approver email
		if approverEmail == "" {
			return fmt.Errorf("approver email cannot be empty")
		}

		// Fix stage numbering - if CurrentStage is 0, set it to 1
		correctStage := request.Status.CurrentStage
		if correctStage == 0 {
			correctStage = 1
			request.Status.CurrentStage = 1
		}

		// Create rejection record
		approval := accessv1alpha1.Approval{
			Stage:     correctStage,
			Approver:  approverEmail,
			Decision:  "rejected",
			Timestamp: metav1.Now(),
			Comment:   reason,
		}

		// Add rejection to the list
		request.Status.Approvals = append(request.Status.Approvals, approval)

		// Update status with the rejection
		if err := c.client.Status().Update(ctx, request); err != nil {
			lastErr = err
			if errors.IsConflict(err) && i < 2 {
				// Retry on conflict
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to update request status: %w", err)
		}

		// Get fresh copy again for annotation update
		if err := c.client.Get(ctx, types.NamespacedName{
			Name:      requestName,
			Namespace: c.namespace,
		}, request); err != nil {
			return fmt.Errorf("failed to get request for annotation update: %w", err)
		}

		// Force reconciliation by updating an annotation
		if request.Annotations == nil {
			request.Annotations = make(map[string]string)
		}

		request.Annotations["eksaccess.io/last-rejection"] = metav1.Now().Format(time.RFC3339)
		request.Annotations["eksaccess.io/last-rejection-by"] = approverEmail

		// This update will trigger the controller to reconcile
		if err := c.client.Update(ctx, request); err != nil {
			lastErr = err
			if errors.IsConflict(err) && i < 2 {
				// Retry on conflict
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// Don't fail if only annotation update fails - the rejection is already recorded
			// Just log the error
			if errors.IsConflict(err) {
				// Conflict on annotation is OK - the rejection was recorded
				return nil
			}
			return fmt.Errorf("failed to trigger reconciliation: %w", err)
		}

		// Success
		return nil
	}

	// If we only failed on annotation update but status was updated, that's OK
	if lastErr != nil && errors.IsConflict(lastErr) {
		// The rejection was recorded in status, just couldn't update annotation
		// This is acceptable - the controller will still process it
		return nil
	}

	return fmt.Errorf("failed after retries: %w", lastErr)
}

// GetPendingApprovalsForUser gets all requests waiting for approval from a specific user
func (c *K8sClient) GetPendingApprovalsForUser(ctx context.Context, userEmail string) ([]*accessv1alpha1.EKSAccessRequest, error) {
	requestList := &accessv1alpha1.EKSAccessRequestList{}
	if err := c.client.List(ctx, requestList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list requests: %w", err)
	}

	var pendingRequests []*accessv1alpha1.EKSAccessRequest

	for i := range requestList.Items {
		req := &requestList.Items[i]

		if req.Status.State != accessv1alpha1.StateAwaitingApproval {
			continue
		}

		policyName := req.Annotations[annotationApprovalPolicy]
		if policyName == "" {
			continue
		}

		policy := &accessv1alpha1.ApprovalPolicy{}
		if err := c.client.Get(ctx, types.NamespacedName{
			Name:      policyName,
			Namespace: req.Namespace,
		}, policy); err != nil {
			continue
		}

		for _, stage := range policy.Spec.Stages {
			if stage.StageNumber == req.Status.CurrentStage {
				for _, approver := range stage.Approvers {
					if approver == userEmail {
						alreadyActed := false
						for _, approval := range req.Status.Approvals {
							if approval.Stage == req.Status.CurrentStage && approval.Approver == userEmail {
								alreadyActed = true
								break
							}
						}

						if !alreadyActed {
							pendingRequests = append(pendingRequests, req)
						}
						break
					}
				}
				break
			}
		}
	}

	return pendingRequests, nil
}

// GetRequestBySlackMessage retrieves a request by Slack message metadata
func (c *K8sClient) GetRequestBySlackMessage(ctx context.Context, channelID, messageTS string) (*accessv1alpha1.EKSAccessRequest, error) {
	requestList := &accessv1alpha1.EKSAccessRequestList{}
	if err := c.client.List(ctx, requestList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list requests: %w", err)
	}

	for i := range requestList.Items {
		req := &requestList.Items[i]
		if req.Status.SlackMessages != nil {
			for _, msg := range req.Status.SlackMessages {
				if msg.ChannelID == channelID && msg.Timestamp == messageTS {
					return req, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("request not found for message")
}

// UpdateSlackMessageMetadata updates the Slack message metadata in the request status
func (c *K8sClient) UpdateSlackMessageMetadata(ctx context.Context, requestName string, messageKey string, info accessv1alpha1.SlackMessageInfo) error {
	request := &accessv1alpha1.EKSAccessRequest{}
	if err := c.client.Get(ctx, types.NamespacedName{
		Name:      requestName,
		Namespace: c.namespace,
	}, request); err != nil {
		return fmt.Errorf("failed to get request: %w", err)
	}

	if request.Status.SlackMessages == nil {
		request.Status.SlackMessages = make(map[string]accessv1alpha1.SlackMessageInfo)
	}

	request.Status.SlackMessages[messageKey] = info

	if err := c.client.Status().Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update request status: %w", err)
	}

	return nil
}

// GetAccessRequest retrieves a specific access request by name
func (c *K8sClient) GetAccessRequest(ctx context.Context, requestName string) (*accessv1alpha1.EKSAccessRequest, error) {
	request := &accessv1alpha1.EKSAccessRequest{}
	if err := c.client.Get(ctx, types.NamespacedName{
		Name:      requestName,
		Namespace: c.namespace,
	}, request); err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}
	return request, nil
}

// ListAccessRequests lists all access requests in the namespace
func (c *K8sClient) ListAccessRequests(ctx context.Context) ([]*accessv1alpha1.EKSAccessRequest, error) {
	requestList := &accessv1alpha1.EKSAccessRequestList{}
	if err := c.client.List(ctx, requestList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list requests: %w", err)
	}

	var requests []*accessv1alpha1.EKSAccessRequest
	for i := range requestList.Items {
		requests = append(requests, &requestList.Items[i])
	}

	return requests, nil
}

// GetApprovalPolicy retrieves an approval policy by name
func (c *K8sClient) GetApprovalPolicy(ctx context.Context, policyName string) (*accessv1alpha1.ApprovalPolicy, error) {
	policy := &accessv1alpha1.ApprovalPolicy{}
	if err := c.client.Get(ctx, types.NamespacedName{
		Name:      policyName,
		Namespace: c.namespace,
	}, policy); err != nil {
		return nil, fmt.Errorf("failed to get approval policy: %w", err)
	}
	return policy, nil
}

// ListApprovalPolicies lists all approval policies in the namespace
func (c *K8sClient) ListApprovalPolicies(ctx context.Context) ([]*accessv1alpha1.ApprovalPolicy, error) {
	policyList := &accessv1alpha1.ApprovalPolicyList{}
	if err := c.client.List(ctx, policyList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list approval policies: %w", err)
	}

	var policies []*accessv1alpha1.ApprovalPolicy
	for i := range policyList.Items {
		policies = append(policies, &policyList.Items[i])
	}

	return policies, nil
}

// GetEnabledAWSAccounts returns all enabled AWS accounts
func (c *K8sClient) GetEnabledAWSAccounts(ctx context.Context) ([]*accessv1alpha1.AWSAccount, error) {
	accountList := &accessv1alpha1.AWSAccountList{}
	if err := c.client.List(ctx, accountList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list AWS accounts: %w", err)
	}

	var accounts []*accessv1alpha1.AWSAccount
	for i := range accountList.Items {
		account := &accountList.Items[i]
		if account.Spec.Enabled {
			accounts = append(accounts, account)
		}
	}

	// Sort by name for consistent ordering
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].Spec.Name < accounts[j].Spec.Name
	})

	return accounts, nil
}

// GetEnabledIAMRolesForAccount returns all enabled IAM roles for a specific AWS account
func (c *K8sClient) GetEnabledIAMRolesForAccount(ctx context.Context, accountID string, userEmail string) ([]*accessv1alpha1.IAMRole, error) {
	roleList := &accessv1alpha1.IAMRoleList{}
	if err := c.client.List(ctx, roleList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list IAM roles: %w", err)
	}

	var roles []*accessv1alpha1.IAMRole
	for i := range roleList.Items {
		role := &roleList.Items[i]
		// Filter by account and enabled status
		if role.Spec.Enabled && role.Spec.AccountID == accountID {
			// Check if user is in allowed principals (if specified)
			if len(role.Spec.AllowedPrincipals) > 0 {
				allowed := false
				for _, principal := range role.Spec.AllowedPrincipals {
					if principal == userEmail || principal == "*" {
						allowed = true
						break
					}
				}
				if !allowed {
					continue
				}
			}
			roles = append(roles, role)
		}
	}

	// Sort by display name for consistent ordering
	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Spec.DisplayName < roles[j].Spec.DisplayName
	})

	return roles, nil
}

// GetEnabledEKSClustersForAccount returns all enabled EKS clusters for a specific AWS account
func (c *K8sClient) GetEnabledEKSClustersForAccount(ctx context.Context, accountID string) ([]*accessv1alpha1.EKSCluster, error) {
	clusterList := &accessv1alpha1.EKSClusterList{}
	if err := c.client.List(ctx, clusterList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list EKS clusters: %w", err)
	}

	var clusters []*accessv1alpha1.EKSCluster
	for i := range clusterList.Items {
		cluster := &clusterList.Items[i]
		// Filter by account and enabled status
		if cluster.Spec.Enabled && cluster.Spec.AccountID == accountID {
			clusters = append(clusters, cluster)
		}
	}

	// Sort by cluster name for consistent ordering
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].Spec.ClusterName < clusters[j].Spec.ClusterName
	})

	return clusters, nil
}

// GetAccessPoliciesForCluster returns supported access policies for a specific cluster
func (c *K8sClient) GetAccessPoliciesForCluster(ctx context.Context, clusterName string, accountID string) ([]string, error) {
	// Try to find cluster by name and account
	clusterList := &accessv1alpha1.EKSClusterList{}
	if err := c.client.List(ctx, clusterList, client.InNamespace(c.namespace)); err != nil {
		return nil, fmt.Errorf("failed to list EKS clusters: %w", err)
	}

	var foundCluster *accessv1alpha1.EKSCluster
	for i := range clusterList.Items {
		cl := &clusterList.Items[i]
		if cl.Spec.ClusterName == clusterName && cl.Spec.AccountID == accountID {
			foundCluster = cl
			break
		}
	}

	if foundCluster == nil {
		// Return default policies if cluster not found
		return []string{
			"AmazonEKSViewPolicy",
			"AmazonEKSEditPolicy",
			"AmazonEKSAdminPolicy",
			"AmazonEKSClusterAdminPolicy",
		}, nil
	}

	// If cluster has specific supported policies, return those
	if len(foundCluster.Spec.SupportedAccessPolicies) > 0 {
		return foundCluster.Spec.SupportedAccessPolicies, nil
	}

	// Otherwise return default policies
	return []string{
		"AmazonEKSViewPolicy",
		"AmazonEKSEditPolicy",
		"AmazonEKSAdminPolicy",
		"AmazonEKSClusterAdminPolicy",
	}, nil
}

// ResourceOptions contains dropdown options for modal
type ResourceOptions struct {
	Accounts       []*accessv1alpha1.AWSAccount
	IAMRoles       map[string][]*accessv1alpha1.IAMRole    // keyed by accountID
	EKSClusters    map[string][]*accessv1alpha1.EKSCluster // keyed by accountID
	AccessPolicies map[string][]string                     // keyed by "accountID:clusterName"
}

// GetResourceOptionsForUser returns all resource options for a user to populate dropdowns
func (c *K8sClient) GetResourceOptionsForUser(ctx context.Context, userEmail string) (*ResourceOptions, error) {
	options := &ResourceOptions{
		IAMRoles:       make(map[string][]*accessv1alpha1.IAMRole),
		EKSClusters:    make(map[string][]*accessv1alpha1.EKSCluster),
		AccessPolicies: make(map[string][]string),
	}

	// Get all enabled accounts
	accounts, err := c.GetEnabledAWSAccounts(ctx)
	if err != nil {
		return nil, err
	}
	options.Accounts = accounts

	// For each account, get roles and clusters
	for _, account := range accounts {
		// Get IAM roles for this account
		roles, err := c.GetEnabledIAMRolesForAccount(ctx, account.Spec.AccountID, userEmail)
		if err != nil {
			continue // Skip on error
		}
		if len(roles) > 0 {
			options.IAMRoles[account.Spec.AccountID] = roles
		}

		// Get EKS clusters for this account
		clusters, err := c.GetEnabledEKSClustersForAccount(ctx, account.Spec.AccountID)
		if err != nil {
			continue // Skip on error
		}
		if len(clusters) > 0 {
			options.EKSClusters[account.Spec.AccountID] = clusters

			// Get access policies for each cluster
			for _, cluster := range clusters {
				key := fmt.Sprintf("%s:%s", account.Spec.AccountID, cluster.Spec.ClusterName)
				policies, _ := c.GetAccessPoliciesForCluster(ctx, cluster.Spec.ClusterName, account.Spec.AccountID)
				options.AccessPolicies[key] = policies
			}
		}
	}

	return options, nil
}

type AccessRequestInput struct {
	RequestorEmail string
	SlackUserID    string
	SlackChannelID string
	IAMRole        string
	AWSAccount     string
	Cluster        string
	AccessPolicy   string
	Reason         string
	Duration       string
}

func sanitizeLabel(value string) string {
	// Remove special characters and convert to lowercase
	reg := regexp.MustCompile("[^a-zA-Z0-9._-]")
	sanitized := reg.ReplaceAllString(strings.ToLower(value), "-")

	// Remove consecutive dashes
	reg = regexp.MustCompile("-+")
	sanitized = reg.ReplaceAllString(sanitized, "-")

	// Remove leading/trailing dashes
	sanitized = strings.Trim(sanitized, "-")

	// Truncate to 63 characters (Kubernetes label limit)
	if len(sanitized) > 63 {
		sanitized = sanitized[:63]
		sanitized = strings.TrimRight(sanitized, "-")
	}

	// Ensure it's not empty
	if sanitized == "" {
		sanitized = "default"
	}

	return sanitized
}
