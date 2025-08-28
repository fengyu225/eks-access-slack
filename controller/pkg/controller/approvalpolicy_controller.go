/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	accessv1alpha1 "eks-access-slack/controller/api/v1alpha1"
)

const (
	policyFinalizerName = "approvalpolicy.eksaccess.io/finalizer"
)

var validAccessPolicies = []string{
	"AmazonEKSViewPolicy",
	"AmazonEKSEditPolicy",
	"AmazonEKSAdminPolicy",
	"AmazonEKSClusterAdminPolicy",
}

// ApprovalPolicyReconciler reconciles a ApprovalPolicy object
type ApprovalPolicyReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=access.eksaccess.io,resources=approvalpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=approvalpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=approvalpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=eksaccessrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

func (r *ApprovalPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("approvalpolicy", req.NamespacedName)
	log.Info("Reconciling ApprovalPolicy")

	policy := &accessv1alpha1.ApprovalPolicy{}
	err := r.Get(ctx, req.NamespacedName, policy)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("ApprovalPolicy not found, likely deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get ApprovalPolicy")
		return ctrl.Result{}, err
	}

	if !controllerutil.ContainsFinalizer(policy, policyFinalizerName) {
		log.Info("Adding finalizer")
		controllerutil.AddFinalizer(policy, policyFinalizerName)
		if err := r.Update(ctx, policy); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if !policy.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("Handling deletion")
		return r.handleDeletion(ctx, policy)
	}

	if err := r.validatePolicy(policy); err != nil {
		log.Error(err, "Policy validation failed")

		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Valid",
			Status:             metav1.ConditionFalse,
			ObservedGeneration: policy.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "ValidationFailed",
			Message:            err.Error(),
		})

		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               "Valid",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: policy.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             "Validated",
		Message:            "Policy is valid",
	})

	activeRequests, err := r.countActiveRequests(ctx, policy)
	if err != nil {
		log.Error(err, "Failed to count active requests")
		return ctrl.Result{}, err
	}

	policy.Status.ActiveRequests = activeRequests

	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		ObservedGeneration: policy.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             "PolicyReady",
		Message:            fmt.Sprintf("Policy is ready with %d active requests", activeRequests),
	})

	if err := r.Status().Update(ctx, policy); err != nil {
		log.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
}

func (r *ApprovalPolicyReconciler) handleDeletion(ctx context.Context, policy *accessv1alpha1.ApprovalPolicy) (ctrl.Result, error) {
	log := r.Log.WithValues("approvalpolicy", policy.Name)

	activeRequests, err := r.countActiveRequests(ctx, policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	if activeRequests > 0 {
		log.Info("Cannot delete policy with active requests", "activeRequests", activeRequests)

		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "DeletionBlocked",
			Status:             metav1.ConditionTrue,
			ObservedGeneration: policy.Generation,
			LastTransitionTime: metav1.Now(),
			Reason:             "ActiveRequests",
			Message:            fmt.Sprintf("Cannot delete policy with %d active requests", activeRequests),
		})

		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	controllerutil.RemoveFinalizer(policy, policyFinalizerName)
	if err := r.Update(ctx, policy); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("Successfully removed finalizer")
	return ctrl.Result{}, nil
}

func (r *ApprovalPolicyReconciler) validatePolicy(policy *accessv1alpha1.ApprovalPolicy) error {
	if len(policy.Spec.Stages) == 0 {
		return fmt.Errorf("at least one approval stage is required")
	}

	// Check for duplicate stage numbers
	stageNumbers := make(map[int]bool)
	for _, stage := range policy.Spec.Stages {
		if stageNumbers[stage.StageNumber] {
			return fmt.Errorf("duplicate stage number: %d", stage.StageNumber)
		}
		stageNumbers[stage.StageNumber] = true

		if stage.Name == "" {
			return fmt.Errorf("stage %d: name is required", stage.StageNumber)
		}

		if len(stage.Approvers) == 0 {
			return fmt.Errorf("stage %d: at least one approver is required", stage.StageNumber)
		}

		if stage.RequiredApprovals < 1 {
			return fmt.Errorf("stage %d: required approvals must be at least 1", stage.StageNumber)
		}

		if stage.RequiredApprovals > len(stage.Approvers) {
			return fmt.Errorf("stage %d: required approvals (%d) cannot exceed number of approvers (%d)",
				stage.StageNumber, stage.RequiredApprovals, len(stage.Approvers))
		}

		if stage.Timeout != "" {
			if _, err := time.ParseDuration(stage.Timeout); err != nil {
				return fmt.Errorf("stage %d: invalid timeout format: %v", stage.StageNumber, err)
			}
		}
	}

	// Validate stage numbers are sequential starting from 1
	for i := 1; i <= len(policy.Spec.Stages); i++ {
		if !stageNumbers[i] {
			return fmt.Errorf("missing stage number: %d", i)
		}
	}

	if policy.Spec.MaxAccessDuration != "" {
		if _, err := time.ParseDuration(policy.Spec.MaxAccessDuration); err != nil {
			return fmt.Errorf("invalid max access duration format: %v", err)
		}
	}

	if err := r.validatePolicyConditions(policy.Spec.Conditions); err != nil {
		return fmt.Errorf("invalid conditions: %v", err)
	}

	return nil
}

func (r *ApprovalPolicyReconciler) validatePolicyConditions(conditions accessv1alpha1.PolicyCondition) error {
	// Validate account IDs
	for _, account := range conditions.Accounts {
		if !regexp.MustCompile(`^\d{12}$`).MatchString(account) {
			return fmt.Errorf("invalid AWS account ID: %s", account)
		}
	}

	// Validate IAM role patterns are valid regex
	for _, pattern := range conditions.IAMRolePatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid IAM role pattern: %s: %v", pattern, err)
		}
	}

	// Validate requester patterns are valid regex
	for _, pattern := range conditions.RequesterPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid requester pattern: %s: %v", pattern, err)
		}
	}

	for _, policy := range conditions.AccessPolicies {
		valid := false
		for _, validPolicy := range validAccessPolicies {
			if policy == validPolicy {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid access policy: %s", policy)
		}
	}

	return nil
}

func (r *ApprovalPolicyReconciler) countActiveRequests(ctx context.Context, policy *accessv1alpha1.ApprovalPolicy) (int, error) {
	requests := &accessv1alpha1.EKSAccessRequestList{}
	if err := r.List(ctx, requests); err != nil {
		return 0, err
	}

	count := 0
	for _, req := range requests.Items {
		if policyName, ok := req.Annotations["eksaccess.io/approval-policy"]; ok && policyName == policy.Name {
			switch req.Status.State {
			case accessv1alpha1.StatePending,
				accessv1alpha1.StateAwaitingApproval,
				accessv1alpha1.StateApproved,
				accessv1alpha1.StateProvisioning,
				accessv1alpha1.StateActive:
				count++
			}
		}
	}

	return count, nil
}

func (r *ApprovalPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("approvalpolicy-controller").
		For(&accessv1alpha1.ApprovalPolicy{}).
		Complete(r)
}
