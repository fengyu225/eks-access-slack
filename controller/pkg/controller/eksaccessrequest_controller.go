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
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	accessv1alpha1 "eks-access-slack/controller/api/v1alpha1"
)

const (
	finalizerName = "eksaccess.io/finalizer"

	// Annotations
	annotationApprovalPolicy = "eksaccess.io/approval-policy"
	annotationNotifiedStage  = "eksaccess.io/notified-stage"

	// Condition types
	ConditionPolicyMatched    = "PolicyMatched"
	ConditionApprovalRequired = "ApprovalRequired"
	ConditionProvisioned      = "Provisioned"
	ConditionExpired          = "Expired"

	// Events
	EventRequestCreated     = "RequestCreated"
	EventApprovalRequired   = "ApprovalRequired"
	EventApproved           = "Approved"
	EventRejected           = "Rejected"
	EventProvisioned        = "Provisioned"
	EventProvisioningFailed = "ProvisioningFailed"
	EventExpired            = "Expired"
	EventRevoked            = "Revoked"

	defaultExpiration = 24 * time.Hour
)

// EKSAccessRequestReconciler reconciles a EKSAccessRequest object
type EKSAccessRequestReconciler struct {
	client.Client
	Log               logr.Logger
	Scheme            *runtime.Scheme
	Recorder          record.EventRecorder
	eksClients        map[string]*eks.Client
	DefaultRegion     string
	NotificationQueue chan accessv1alpha1.NotificationEvent
}

// +kubebuilder:rbac:groups=access.eksaccess.io,resources=eksaccessrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=eksaccessrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=eksaccessrequests/finalizers,verbs=update
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=approvalpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=approvalpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=approvalpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=awsaccounts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=awsaccounts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=eksclusters,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=eksclusters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=iamroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=iamroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch

func (r *EKSAccessRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.NamespacedName)
	log.Info("Reconciling EKSAccessRequest")

	accessRequest := &accessv1alpha1.EKSAccessRequest{}
	err := r.Get(ctx, req.NamespacedName, accessRequest)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("EKSAccessRequest not found, likely deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get EKSAccessRequest")
		return ctrl.Result{}, err
	}

	if accessRequest.Status.State == "" {
		accessRequest.Status.State = accessv1alpha1.StatePending
		r.Recorder.Event(accessRequest, corev1.EventTypeNormal, EventRequestCreated,
			fmt.Sprintf("Access request created by %s", accessRequest.Spec.Requestor))
	}

	if !controllerutil.ContainsFinalizer(accessRequest, finalizerName) {
		log.Info("Adding finalizer")
		controllerutil.AddFinalizer(accessRequest, finalizerName)
		if err := r.Update(ctx, accessRequest); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if !accessRequest.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("Handling deletion")
		return r.handleDeletion(ctx, accessRequest)
	}

	return r.processStateMachine(ctx, accessRequest)
}

func (r *EKSAccessRequestReconciler) processStateMachine(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name, "state", req.Status.State)

	// Recovery logic for stuck "pending" requests with approvals or rejections
	if req.Status.State == accessv1alpha1.StatePending && len(req.Status.Approvals) > 0 {
		log.Info("Detected stuck request with approvals/rejections, attempting recovery")

		// Check if we have a valid approval policy
		policy, err := r.getApprovalPolicy(ctx, req)
		if err != nil || policy == nil {
			return r.transitionToFailed(ctx, req, "Cannot recover: approval policy not found")
		}

		// If CurrentStage is 0, fix it
		if req.Status.CurrentStage == 0 {
			req.Status.CurrentStage = 1
		}

		// Check for rejections first
		approvals, rejections := r.countStageApprovals(req, req.Status.CurrentStage)

		if rejections > 0 {
			// Handle rejection - transition directly to rejected state
			req.Status.State = accessv1alpha1.StateRejected
			req.Status.Message = "Request was rejected"
			now := metav1.Now()
			req.Status.LastTransitionTime = &now

			// Only send notification if not already sent
			if req.Annotations == nil {
				req.Annotations = make(map[string]string)
			}

			if req.Annotations["eksaccess.io/rejection-notified"] != "true" {
				if r.NotificationQueue != nil {
					notification := accessv1alpha1.NotificationEvent{
						Type:    "request_rejected",
						Request: req.DeepCopy(),
						Action:  "rejected",
					}

					select {
					case r.NotificationQueue <- notification:
						log.Info("Sent rejection notification to requester", "requester", req.Spec.Requestor)
						req.Annotations["eksaccess.io/rejection-notified"] = "true"
						if err := r.Update(ctx, req); err != nil {
							log.Error(err, "Failed to update rejection notification annotation")
						}
					case <-time.After(5 * time.Second):
						log.Error(nil, "Failed to send rejection notification - queue timeout")
					}
				}
			}

			r.Recorder.Event(req, corev1.EventTypeWarning, EventRejected, req.Status.Message)
			return r.updateStatus(ctx, req)
		}

		// Handle approvals
		if approvals >= policy.Spec.Stages[req.Status.CurrentStage-1].RequiredApprovals {
			// Check if all stages are complete
			if req.Status.CurrentStage >= len(policy.Spec.Stages) {
				req.Status.State = accessv1alpha1.StateApproved
				req.Status.Message = "All approval stages completed (recovered)"
			} else {
				req.Status.State = accessv1alpha1.StateAwaitingApproval
				req.Status.CurrentStage++
				req.Status.Message = fmt.Sprintf("Awaiting approval from stage %d", req.Status.CurrentStage)
			}
		} else {
			req.Status.State = accessv1alpha1.StateAwaitingApproval
			req.Status.Message = fmt.Sprintf("Awaiting approval from stage %d (recovered)", req.Status.CurrentStage)
		}

		now := metav1.Now()
		req.Status.LastTransitionTime = &now
		return r.updateStatus(ctx, req)
	}

	switch req.Status.State {
	case accessv1alpha1.StatePending:
		return r.handlePendingState(ctx, req)
	case accessv1alpha1.StateAwaitingApproval:
		return r.handleAwaitingApprovalState(ctx, req)
	case accessv1alpha1.StateApproved:
		return r.handleApprovedState(ctx, req)
	case accessv1alpha1.StateProvisioning:
		return r.handleProvisioningState(ctx, req)
	case accessv1alpha1.StateActive:
		return r.handleActiveState(ctx, req)
	case accessv1alpha1.StateRejected, accessv1alpha1.StateExpired,
		accessv1alpha1.StateRevoked, accessv1alpha1.StateFailed:
		return r.handleTerminalState(ctx, req)
	default:
		log.Error(nil, "Unknown state, resetting to pending", "state", req.Status.State)
		req.Status.State = accessv1alpha1.StatePending
		return r.updateStatus(ctx, req)
	}
}

func (r *EKSAccessRequestReconciler) handlePendingState(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name)
	log.Info("Processing pending state")

	// Check if we already processed this state and sent notifications
	if req.Annotations != nil && req.Annotations["eksaccess.io/pending-processed"] == "true" {
		log.Info("Pending state already processed, skipping")
		return ctrl.Result{}, nil
	}

	if err := r.validateRequest(ctx, req); err != nil {
		log.Error(err, "Request validation failed")
		return r.transitionToFailed(ctx, req, fmt.Sprintf("Validation failed: %v", err))
	}

	policy, err := r.findMatchingPolicy(ctx, req)
	if err != nil {
		log.Error(err, "Failed to find approval policy")
		return ctrl.Result{}, err
	}

	if policy == nil {
		return r.transitionToFailed(ctx, req, "No approval policy found")
	}

	if req.Annotations == nil {
		req.Annotations = make(map[string]string)
	}
	req.Annotations[annotationApprovalPolicy] = policy.Name
	req.Annotations["eksaccess.io/pending-processed"] = "true"

	meta.SetStatusCondition(&req.Status.Conditions, metav1.Condition{
		Type:               ConditionPolicyMatched,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: req.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             "PolicyFound",
		Message:            fmt.Sprintf("Using policy: %s", policy.Name),
	})

	if policy.Spec.AutoApprove {
		log.Info("Auto-approving request per policy")
		req.Status.State = accessv1alpha1.StateApproved
		req.Status.Message = "Auto-approved by policy"
		r.Recorder.Event(req, corev1.EventTypeNormal, EventApproved, "Auto-approved by policy")

		// Update annotations and resource
		if err := r.Update(ctx, req); err != nil {
			return ctrl.Result{}, err
		}

		return r.updateStatus(ctx, req)
	}

	// Initialize approval workflow
	req.Status.CurrentStage = 1
	req.Status.Approvals = []accessv1alpha1.Approval{}
	req.Status.State = accessv1alpha1.StateAwaitingApproval
	req.Status.Message = fmt.Sprintf("Awaiting approval from stage 1: %s", policy.Spec.Stages[0].Name)

	r.Recorder.Event(req, corev1.EventTypeNormal, EventApprovalRequired,
		fmt.Sprintf("Approval required from stage 1: %s", policy.Spec.Stages[0].Name))

	// Mark stage 1 as needing notification
	req.Annotations["eksaccess.io/stage-1-notified"] = "false"

	// Update the resource first (for any metadata changes)
	if err := r.Update(ctx, req); err != nil {
		return ctrl.Result{}, err
	}

	// Update status separately
	if err := r.Status().Update(ctx, req); err != nil {
		return ctrl.Result{}, err
	}

	// Send notification to Slack only if not already sent
	if r.NotificationQueue != nil && req.Annotations["eksaccess.io/stage-1-notified"] != "true" {
		notification := accessv1alpha1.NotificationEvent{
			Type:      "approval_required",
			Request:   req.DeepCopy(),
			Policy:    policy,
			Stage:     1,
			Approvers: policy.Spec.Stages[0].Approvers,
		}

		select {
		case r.NotificationQueue <- notification:
			log.Info("Sent approval notification to queue", "stage", 1)
			req.Annotations["eksaccess.io/stage-1-notified"] = "true"
			if err := r.Update(ctx, req); err != nil {
				log.Error(err, "Failed to update notification annotation")
			}
		case <-time.After(5 * time.Second):
			log.Error(nil, "Failed to send notification - queue timeout")
		}
	}

	return ctrl.Result{}, nil
}

func (r *EKSAccessRequestReconciler) handleAwaitingApprovalState(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name, "stage", req.Status.CurrentStage)
	log.Info("Processing awaiting approval state")

	policy, err := r.getApprovalPolicy(ctx, req)
	if err != nil {
		return ctrl.Result{}, err
	}

	if policy == nil {
		return r.transitionToFailed(ctx, req, "Approval policy not found")
	}

	var currentStage *accessv1alpha1.ApprovalStage
	for _, stage := range policy.Spec.Stages {
		if stage.StageNumber == req.Status.CurrentStage {
			currentStage = &stage
			break
		}
	}

	if currentStage == nil {
		return r.transitionToFailed(ctx, req, "Invalid approval stage")
	}

	approvals, rejections := r.countStageApprovals(req, req.Status.CurrentStage)

	log.Info("Stage approval status", "approvals", approvals, "rejections", rejections,
		"required", currentStage.RequiredApprovals)

	if rejections > 0 {
		req.Status.State = accessv1alpha1.StateRejected
		req.Status.Message = fmt.Sprintf("Rejected at stage %d", req.Status.CurrentStage)
		r.Recorder.Event(req, corev1.EventTypeWarning, EventRejected, req.Status.Message)

		// Send rejection notification to requester only if not already sent
		if req.Annotations == nil {
			req.Annotations = make(map[string]string)
		}

		if r.NotificationQueue != nil && req.Annotations["eksaccess.io/rejection-notified"] != "true" {
			notification := accessv1alpha1.NotificationEvent{
				Type:    "request_rejected",
				Request: req.DeepCopy(),
				Action:  "rejected",
			}

			select {
			case r.NotificationQueue <- notification:
				log.Info("Sent rejection notification to requester", "requester", req.Spec.Requestor)
				req.Annotations["eksaccess.io/rejection-notified"] = "true"
				if err := r.Update(ctx, req); err != nil {
					log.Error(err, "Failed to update rejection annotation")
				}
			case <-time.After(5 * time.Second):
				log.Error(nil, "Failed to send rejection notification - queue timeout")
			}
		}

		return r.updateStatus(ctx, req)
	}

	if approvals >= currentStage.RequiredApprovals {
		if req.Status.CurrentStage < len(policy.Spec.Stages) {
			req.Status.CurrentStage++
			nextStage := policy.Spec.Stages[req.Status.CurrentStage-1]

			req.Status.Message = fmt.Sprintf("Awaiting approval from stage %d: %s",
				req.Status.CurrentStage, nextStage.Name)

			r.Recorder.Event(req, corev1.EventTypeNormal, EventApprovalRequired, req.Status.Message)

			// Check if we already sent notification for this new stage
			stageNotificationKey := fmt.Sprintf("eksaccess.io/stage-%d-notified", req.Status.CurrentStage)

			if req.Annotations == nil {
				req.Annotations = make(map[string]string)
			}

			if err := r.Update(ctx, req); err != nil {
				return ctrl.Result{}, err
			}

			// Send notification for next stage only if not already sent
			if r.NotificationQueue != nil && req.Annotations[stageNotificationKey] != "true" {
				notification := accessv1alpha1.NotificationEvent{
					Type:      "approval_required",
					Request:   req.DeepCopy(),
					Policy:    policy,
					Stage:     req.Status.CurrentStage,
					Approvers: nextStage.Approvers,
				}

				select {
				case r.NotificationQueue <- notification:
					log.Info("Sent approval notification to queue", "stage", req.Status.CurrentStage)
					req.Annotations[stageNotificationKey] = "true"
					if err := r.Update(ctx, req); err != nil {
						log.Error(err, "Failed to update notification annotation")
					}
				case <-time.After(5 * time.Second):
					log.Error(nil, "Failed to send notification - queue timeout")
				}
			}

			return r.updateStatus(ctx, req)
		} else {
			req.Status.State = accessv1alpha1.StateApproved
			req.Status.Message = "All approval stages completed"
			r.Recorder.Event(req, corev1.EventTypeNormal, EventApproved, "All approval stages completed")
			return r.updateStatus(ctx, req)
		}
	}

	// Check for timeout
	if currentStage.Timeout != "" {
		timeout, err := time.ParseDuration(currentStage.Timeout)
		if err == nil && req.Status.LastTransitionTime != nil {
			if time.Since(req.Status.LastTransitionTime.Time) > timeout {
				req.Status.State = accessv1alpha1.StateExpired
				req.Status.Message = fmt.Sprintf("Approval timeout at stage %d", req.Status.CurrentStage)
				r.Recorder.Event(req, corev1.EventTypeWarning, EventExpired, req.Status.Message)
				return r.updateStatus(ctx, req)
			}
		}
	}

	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *EKSAccessRequestReconciler) handleApprovedState(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name)
	log.Info("Processing approved state")

	// Check if we already sent approval notification
	if req.Annotations == nil {
		req.Annotations = make(map[string]string)
	}

	if req.Annotations["eksaccess.io/approval-notified"] != "true" {
		// Send approval notification to requester
		if r.NotificationQueue != nil {
			notification := accessv1alpha1.NotificationEvent{
				Type:    "request_approved",
				Request: req.DeepCopy(),
				Action:  "approved",
			}

			select {
			case r.NotificationQueue <- notification:
				log.Info("Sent approval notification to requester", "requester", req.Spec.Requestor)
				req.Annotations["eksaccess.io/approval-notified"] = "true"
				if err := r.Update(ctx, req); err != nil {
					log.Error(err, "Failed to update approval notification annotation")
				}
			case <-time.After(5 * time.Second):
				log.Error(nil, "Failed to send approval notification - queue timeout")
			}
		}
	}

	// Set expiration time if not set
	if req.Spec.ExpirationTime == nil {
		policy, _ := r.getApprovalPolicy(ctx, req)
		duration := defaultExpiration
		if policy != nil && policy.Spec.MaxAccessDuration != "" {
			if d, err := time.ParseDuration(policy.Spec.MaxAccessDuration); err == nil {
				duration = d
			}
		}
		expTime := metav1.NewTime(time.Now().Add(duration))
		req.Spec.ExpirationTime = &expTime
		if err := r.Update(ctx, req); err != nil {
			return ctrl.Result{}, err
		}
	}

	req.Status.State = accessv1alpha1.StateProvisioning
	req.Status.Message = "Creating EKS access entry"
	now := metav1.Now()
	req.Status.LastTransitionTime = &now

	return r.updateStatus(ctx, req)
}

func (r *EKSAccessRequestReconciler) handleProvisioningState(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name)
	log.Info("Provisioning EKS access")

	// Check if access entry already exists (idempotency check)
	exists, err := r.verifyEKSAccessEntry(ctx, req)
	if err != nil {
		log.Error(err, "Failed to verify EKS access entry")
		// Continue to try creating if verification fails
	} else if exists {
		log.Info("EKS access entry already exists, transitioning to active")
		return r.transitionToActive(ctx, req, "Access entry already exists")
	}

	// Try to create the access entry
	err = r.createEKSAccessEntry(ctx, req)
	if err != nil {
		// Check if it's a "already exists" error
		if strings.Contains(err.Error(), "ResourceInUseException") ||
			strings.Contains(err.Error(), "already in use") {
			log.Info("Access entry already exists (409 error), transitioning to active")
			return r.transitionToActive(ctx, req, "Access entry created successfully")
		}

		log.Error(err, "Failed to create EKS access entry")

		if isRetryableError(err) {
			req.Status.Message = fmt.Sprintf("Provisioning failed (retrying): %v", err)
			if err := r.Status().Update(ctx, req); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}

		// Non-retryable error - transition to failed
		req.Status.State = accessv1alpha1.StateFailed
		req.Status.Message = fmt.Sprintf("Failed to create access entry: %v", err)
		r.Recorder.Event(req, corev1.EventTypeWarning, EventProvisioningFailed, req.Status.Message)

		// Send failure notification to requester
		if r.NotificationQueue != nil {
			notification := accessv1alpha1.NotificationEvent{
				Type:    "access_terminated",
				Request: req.DeepCopy(),
				Action:  "failed",
			}

			select {
			case r.NotificationQueue <- notification:
				log.Info("Sent failure notification to requester")
			case <-time.After(5 * time.Second):
				log.Error(nil, "Failed to send failure notification")
			}
		}

		return r.updateStatus(ctx, req)
	}

	// Successfully created - transition to active
	return r.transitionToActive(ctx, req, "Access entry created successfully")
}

func (r *EKSAccessRequestReconciler) transitionToActive(ctx context.Context, req *accessv1alpha1.EKSAccessRequest, message string) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name)

	// First, update the status to active
	req.Status.State = accessv1alpha1.StateActive
	req.Status.Message = message
	now := metav1.Now()
	req.Status.LastTransitionTime = &now

	meta.SetStatusCondition(&req.Status.Conditions, metav1.Condition{
		Type:               ConditionProvisioned,
		Status:             metav1.ConditionTrue,
		ObservedGeneration: req.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             "Provisioned",
		Message:            "EKS access entry created",
	})

	// Update status first
	if err := r.Status().Update(ctx, req); err != nil {
		log.Error(err, "Failed to update status to active")
		return ctrl.Result{}, err
	}

	r.Recorder.Event(req, corev1.EventTypeNormal, EventProvisioned,
		fmt.Sprintf("Access granted to %s for cluster %s", req.Spec.Requestor, req.Spec.EKSCluster))

	// Refresh the object after status update to avoid conflicts
	freshReq := &accessv1alpha1.EKSAccessRequest{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(req), freshReq); err != nil {
		log.Error(err, "Failed to get fresh request")
		return ctrl.Result{}, err
	}

	// Check if activation was already notified
	if freshReq.Annotations == nil {
		freshReq.Annotations = make(map[string]string)
	}

	if freshReq.Annotations["eksaccess.io/activation-notified"] != "true" {
		// Send activation notification to requester
		if r.NotificationQueue != nil {
			notification := accessv1alpha1.NotificationEvent{
				Type:    "access_active",
				Request: freshReq.DeepCopy(),
				Action:  "activated",
			}

			select {
			case r.NotificationQueue <- notification:
				log.Info("Sent activation notification to requester")
				freshReq.Annotations["eksaccess.io/activation-notified"] = "true"

				// Update only the annotation on the fresh object
				if err := r.Update(ctx, freshReq); err != nil {
					// Log but don't fail - the important part (status update) succeeded
					log.Error(err, "Failed to update activation notification annotation")
				}
			case <-time.After(5 * time.Second):
				log.Error(nil, "Failed to send activation notification")
			}
		}
	}

	// Return success - the state transition is complete
	return ctrl.Result{}, nil
}

func (r *EKSAccessRequestReconciler) handleActiveState(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name)

	// Check if expired
	if req.Spec.ExpirationTime != nil && req.Spec.ExpirationTime.Time.Before(time.Now()) {
		log.Info("Access expired, removing EKS access entry")

		// Try to delete the EKS access entry
		err := r.deleteEKSAccessEntry(ctx, req)
		if err != nil {
			log.Error(err, "Failed to delete expired access entry, will retry")
			// Retry deletion on next reconciliation
			return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
		}

		// Successfully deleted or doesn't exist
		req.Status.State = accessv1alpha1.StateExpired
		req.Status.Message = "Access period expired"
		req.Status.EKSAccessEntryArn = "" // Clear the ARN since it's deleted

		r.Recorder.Event(req, corev1.EventTypeNormal, EventExpired, "Access expired and removed")

		// Send expiration notification to requester
		if r.NotificationQueue != nil {
			notification := accessv1alpha1.NotificationEvent{
				Type:    "access_terminated",
				Request: req.DeepCopy(),
				Action:  "expired",
			}

			select {
			case r.NotificationQueue <- notification:
				log.Info("Sent expiration notification to requester", "requester", req.Spec.Requestor)
			case <-time.After(5 * time.Second):
				log.Error(nil, "Failed to send expiration notification - queue timeout")
			}
		}

		return r.updateStatus(ctx, req)
	}

	// Verify access entry still exists
	exists, err := r.verifyEKSAccessEntry(ctx, req)
	if err != nil {
		log.Error(err, "Failed to verify EKS access entry")
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, nil
	}

	if !exists {
		log.Info("EKS access entry not found, may have been manually deleted")
		req.Status.Message = "Access entry not found (may have been manually deleted)"
		if err := r.Status().Update(ctx, req); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Calculate next requeue time
	var requeueAfter time.Duration
	if req.Spec.ExpirationTime != nil {
		timeUntilExpiry := time.Until(req.Spec.ExpirationTime.Time)
		if timeUntilExpiry > 5*time.Minute {
			requeueAfter = 5 * time.Minute
		} else if timeUntilExpiry > 0 {
			requeueAfter = timeUntilExpiry + 10*time.Second
		} else {
			// Already expired, requeue quickly to handle it
			requeueAfter = 10 * time.Second
		}
	} else {
		requeueAfter = 5 * time.Minute
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *EKSAccessRequestReconciler) handleTerminalState(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name, "state", req.Status.State)
	log.Info("Request in terminal state")

	return ctrl.Result{}, nil
}

func (r *EKSAccessRequestReconciler) handleDeletion(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("eksaccessrequest", req.Name)
	log.Info("Processing deletion")

	// Check if finalizer is present
	if !controllerutil.ContainsFinalizer(req, finalizerName) {
		log.Info("Finalizer not present, allowing deletion")
		return ctrl.Result{}, nil
	}

	// Log AWS resources that will need cleanup
	if req.Status.State == accessv1alpha1.StateActive ||
		req.Status.State == accessv1alpha1.StateProvisioning {
		log.Info("AWS resources will be cleaned up by background job",
			"cluster", req.Spec.EKSCluster,
			"principal", req.Spec.IAMRole,
			"account", req.Spec.AWSAccount,
			"state", req.Status.State)

		// Store cleanup metadata in a ConfigMap for the background job
		r.recordPendingCleanup(ctx, req)
	}

	// Remove finalizer immediately
	log.Info("Removing finalizer to allow deletion")
	controllerutil.RemoveFinalizer(req, finalizerName)

	// Update with retry logic
	for i := 0; i < 3; i++ {
		if err := r.Update(ctx, req); err != nil {
			if errors.IsConflict(err) {
				// Refresh and retry
				fresh := &accessv1alpha1.EKSAccessRequest{}
				if getErr := r.Get(ctx, client.ObjectKeyFromObject(req), fresh); getErr != nil {
					if errors.IsNotFound(getErr) {
						// Already deleted
						return ctrl.Result{}, nil
					}
					return ctrl.Result{}, getErr
				}
				req = fresh
				if !controllerutil.ContainsFinalizer(req, finalizerName) {
					// Already removed
					return ctrl.Result{}, nil
				}
				controllerutil.RemoveFinalizer(req, finalizerName)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return ctrl.Result{}, err
		}
		break
	}

	log.Info("Successfully removed finalizer, deletion will proceed")
	return ctrl.Result{}, nil
}

func (r *EKSAccessRequestReconciler) recordPendingCleanup(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) {
	log := r.Log.WithValues("request", req.Name)

	cm := &corev1.ConfigMap{}
	cmKey := k8stypes.NamespacedName{ // Fixed: use types.NamespacedName
		Name:      "eks-pending-cleanups",
		Namespace: req.Namespace,
	}

	if err := r.Get(ctx, cmKey, cm); err != nil {
		if errors.IsNotFound(err) {
			cm = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eks-pending-cleanups",
					Namespace: req.Namespace,
				},
				Data: make(map[string]string),
			}
			if createErr := r.Create(ctx, cm); createErr != nil && !errors.IsAlreadyExists(createErr) {
				log.Error(createErr, "Failed to create cleanup ConfigMap")
				return
			}
		} else {
			log.Error(err, "Failed to get cleanup ConfigMap")
			return
		}
	}

	if cm.Data == nil {
		cm.Data = make(map[string]string)
	}

	// Store cleanup record
	cleanupKey := fmt.Sprintf("%s-%d", req.Name, time.Now().UnixNano())
	cleanupData := fmt.Sprintf("%s|%s|%s|%s|%d",
		req.Spec.AWSAccount,
		req.Spec.EKSCluster,
		req.Spec.IAMRole,
		req.Namespace,
		time.Now().Unix())

	cm.Data[cleanupKey] = cleanupData

	if err := r.Update(ctx, cm); err != nil {
		log.Error(err, "Failed to record pending cleanup")
	} else {
		log.Info("Recorded pending cleanup", "key", cleanupKey)
	}
}

func (r *EKSAccessRequestReconciler) StartCleanupWorker(ctx context.Context, interval time.Duration) {
	log := r.Log.WithName("cleanup-worker")
	log.Info("Starting AWS cleanup worker", "interval", interval)

	go func() {
		// Initial delay to let the controller stabilize
		time.Sleep(30 * time.Second)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Cleanup worker stopping")
				return
			case <-ticker.C:
				log.Info("Running cleanup cycle")
				if err := r.performCleanup(ctx); err != nil {
					log.Error(err, "Cleanup cycle failed")
				}
			}
		}
	}()
}

func (r *EKSAccessRequestReconciler) performCleanup(ctx context.Context) error {
	log := r.Log.WithName("cleanup")

	// Get all namespaces
	namespaces := &corev1.NamespaceList{}
	if err := r.List(ctx, namespaces); err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	totalCleaned := 0
	totalFailed := 0

	for _, ns := range namespaces.Items {
		// Process pending cleanups from ConfigMap
		pendingCleaned, pendingFailed := r.processPendingCleanups(ctx, ns.Name)
		totalCleaned += pendingCleaned
		totalFailed += pendingFailed

		// Look for orphaned AWS resources
		orphanCleaned, orphanFailed := r.cleanOrphanedResources(ctx, ns.Name)
		totalCleaned += orphanCleaned
		totalFailed += orphanFailed
	}

	if totalCleaned > 0 || totalFailed > 0 {
		log.Info("Cleanup cycle completed", "cleaned", totalCleaned, "failed", totalFailed)
	}

	return nil
}

func (r *EKSAccessRequestReconciler) processPendingCleanups(ctx context.Context, namespace string) (cleaned, failed int) {
	log := r.Log.WithName("cleanup").WithValues("namespace", namespace)

	cm := &corev1.ConfigMap{}
	cmKey := k8stypes.NamespacedName{
		Name:      "eks-pending-cleanups",
		Namespace: namespace,
	}

	if err := r.Get(ctx, cmKey, cm); err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "Failed to get cleanup ConfigMap")
		}
		return 0, 0
	}

	if len(cm.Data) == 0 {
		return 0, 0
	}

	keysToDelete := []string{}

	for key, value := range cm.Data {
		parts := strings.Split(value, "|")
		if len(parts) < 5 {
			log.Error(nil, "Invalid cleanup record", "key", key, "value", value)
			keysToDelete = append(keysToDelete, key)
			continue
		}

		accountID := parts[0]
		clusterName := parts[1]
		iamRole := parts[2]
		// namespace := parts[3]
		timestampStr := parts[4]

		// Check age of cleanup request (skip if too recent to allow for race conditions)
		timestamp, _ := strconv.ParseInt(timestampStr, 10, 64)
		age := time.Since(time.Unix(timestamp, 0))
		if age < 30*time.Second {
			log.V(1).Info("Skipping recent cleanup entry", "key", key, "age", age)
			continue
		}

		// Try to delete from AWS
		if err := r.deleteAWSAccessEntry(ctx, accountID, clusterName, iamRole, namespace); err != nil {
			log.Error(err, "Failed to delete AWS access entry",
				"account", accountID,
				"cluster", clusterName,
				"role", iamRole)

			// If it's been more than 1 hour, remove anyway (might be manually deleted)
			if age > time.Hour {
				log.Info("Removing old failed cleanup entry", "key", key, "age", age)
				keysToDelete = append(keysToDelete, key)
			}
			failed++
		} else {
			log.Info("Successfully cleaned AWS access entry",
				"account", accountID,
				"cluster", clusterName,
				"role", iamRole)
			keysToDelete = append(keysToDelete, key)
			cleaned++
		}
	}

	// Remove processed entries
	if len(keysToDelete) > 0 {
		for _, key := range keysToDelete {
			delete(cm.Data, key)
		}
		if err := r.Update(ctx, cm); err != nil {
			log.Error(err, "Failed to update cleanup ConfigMap")
		}
	}

	return cleaned, failed
}

func (r *EKSAccessRequestReconciler) deleteAWSAccessEntry(ctx context.Context, accountID, clusterName, iamRole, namespace string) error {
	// Find cluster configuration
	clusters := &accessv1alpha1.EKSClusterList{}
	if err := r.List(ctx, clusters, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("failed to list clusters: %w", err)
	}

	var eksCluster *accessv1alpha1.EKSCluster
	for i := range clusters.Items {
		cluster := &clusters.Items[i]
		if cluster.Spec.ClusterName == clusterName &&
			cluster.Spec.AccountID == accountID {
			eksCluster = cluster
			break
		}
	}

	if eksCluster == nil {
		return fmt.Errorf("cluster configuration not found: %s in account %s", clusterName, accountID)
	}

	region := eksCluster.Spec.Region
	if region == "" {
		region = r.DefaultRegion
		if region == "" {
			region = "ap-northeast-2"
		}
	}

	eksClient, err := r.getEKSClient(region)
	if err != nil {
		return fmt.Errorf("failed to get EKS client: %w", err)
	}

	// Use a timeout for AWS call
	deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	input := &eks.DeleteAccessEntryInput{
		ClusterName:  &clusterName,
		PrincipalArn: &iamRole,
	}

	_, err = eksClient.DeleteAccessEntry(deleteCtx, input)
	if err != nil {
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			// Already deleted
			return nil
		}
		return fmt.Errorf("failed to delete access entry: %w", err)
	}

	return nil
}

// listAWSAccessEntries lists all access entries for a cluster
func (r *EKSAccessRequestReconciler) listAWSAccessEntries(ctx context.Context, cluster *accessv1alpha1.EKSCluster) ([]AccessEntryInfo, error) {
	region := cluster.Spec.Region
	if region == "" {
		region = r.DefaultRegion
		if region == "" {
			region = "ap-northeast-2"
		}
	}

	eksClient, err := r.getEKSClient(region)
	if err != nil {
		return nil, fmt.Errorf("failed to get EKS client: %w", err)
	}

	listCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	input := &eks.ListAccessEntriesInput{
		ClusterName: &cluster.Spec.ClusterName,
	}

	output, err := eksClient.ListAccessEntries(listCtx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list access entries: %w", err)
	}

	var entries []AccessEntryInfo
	for _, arn := range output.AccessEntries {
		entries = append(entries, AccessEntryInfo{
			PrincipalArn: arn,
		})
	}

	return entries, nil
}

// AccessEntryInfo holds basic info about an AWS EKS access entry
type AccessEntryInfo struct {
	PrincipalArn string
}

func (r *EKSAccessRequestReconciler) cleanOrphanedResources(ctx context.Context, namespace string) (cleaned, failed int) {
	log := r.Log.WithName("cleanup-orphaned").WithValues("namespace", namespace)

	// Build map of expected AWS resources based on active CRDs
	expectedEntries := make(map[string]bool)

	requests := &accessv1alpha1.EKSAccessRequestList{}
	if err := r.List(ctx, requests, client.InNamespace(namespace)); err != nil {
		log.Error(err, "Failed to list access requests")
		return 0, 0
	}

	for _, req := range requests.Items {
		if req.Status.State == accessv1alpha1.StateActive ||
			req.Status.State == accessv1alpha1.StateProvisioning {
			key := fmt.Sprintf("%s|%s|%s",
				req.Spec.AWSAccount,
				req.Spec.EKSCluster,
				req.Spec.IAMRole)
			expectedEntries[key] = true
		}
	}

	// Get all configured clusters
	clusters := &accessv1alpha1.EKSClusterList{}
	if err := r.List(ctx, clusters, client.InNamespace(namespace)); err != nil {
		log.Error(err, "Failed to list clusters")
		return 0, 0
	}

	for _, cluster := range clusters.Items {
		// Skip if disabled
		if !cluster.Spec.Enabled {
			continue
		}

		// List AWS access entries for this cluster
		awsEntries, err := r.listAWSAccessEntries(ctx, &cluster)
		if err != nil {
			log.Error(err, "Failed to list AWS entries",
				"cluster", cluster.Spec.ClusterName,
				"account", cluster.Spec.AccountID)
			continue
		}

		for _, entry := range awsEntries {
			key := fmt.Sprintf("%s|%s|%s",
				cluster.Spec.AccountID,
				cluster.Spec.ClusterName,
				entry.PrincipalArn)

			if !expectedEntries[key] {
				// Found orphaned entry
				log.Info("Found orphaned AWS access entry",
					"cluster", cluster.Spec.ClusterName,
					"principal", entry.PrincipalArn)

				if err := r.deleteAWSAccessEntry(ctx,
					cluster.Spec.AccountID,
					cluster.Spec.ClusterName,
					entry.PrincipalArn,
					namespace); err != nil {
					log.Error(err, "Failed to delete orphaned entry")
					failed++
				} else {
					log.Info("Deleted orphaned entry")
					cleaned++
				}
			}
		}
	}

	return cleaned, failed
}

func (r *EKSAccessRequestReconciler) validateRequest(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) error {
	// Validate email format
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(req.Spec.Requestor) {
		return fmt.Errorf("invalid requestor email format")
	}

	// Validate IAM role ARN format
	arnRegex := regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$`)
	if !arnRegex.MatchString(req.Spec.IAMRole) {
		return fmt.Errorf("invalid IAM role ARN format")
	}

	// Validate AWS account ID
	accountRegex := regexp.MustCompile(`^\d{12}$`)
	if !accountRegex.MatchString(req.Spec.AWSAccount) {
		return fmt.Errorf("invalid AWS account ID format")
	}

	// Validate access policy
	validPolicies := []string{
		"AmazonEKSViewPolicy",
		"AmazonEKSEditPolicy",
		"AmazonEKSAdminPolicy",
		"AmazonEKSClusterAdminPolicy",
	}

	validPolicy := false
	for _, p := range validPolicies {
		if req.Spec.AccessPolicy == p {
			validPolicy = true
			break
		}
	}

	if !validPolicy {
		return fmt.Errorf("invalid access policy: %s", req.Spec.AccessPolicy)
	}

	return nil
}

func (r *EKSAccessRequestReconciler) findMatchingPolicy(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (*accessv1alpha1.ApprovalPolicy, error) {
	policies := &accessv1alpha1.ApprovalPolicyList{}
	if err := r.List(ctx, policies); err != nil {
		return nil, err
	}

	var matchingPolicies []accessv1alpha1.ApprovalPolicy

	for _, policy := range policies.Items {
		if !policy.Spec.Enabled {
			continue
		}

		if r.policyMatchesRequest(&policy, req) {
			matchingPolicies = append(matchingPolicies, policy)
		}
	}

	if len(matchingPolicies) == 0 {
		// Look for default policy
		for _, policy := range policies.Items {
			if policy.Name == "default" && policy.Spec.Enabled {
				return &policy, nil
			}
		}
		return nil, nil
	}

	// Sort by priority (higher priority first)
	sort.Slice(matchingPolicies, func(i, j int) bool {
		return matchingPolicies[i].Spec.Priority > matchingPolicies[j].Spec.Priority
	})

	return &matchingPolicies[0], nil
}

func (r *EKSAccessRequestReconciler) policyMatchesRequest(policy *accessv1alpha1.ApprovalPolicy, req *accessv1alpha1.EKSAccessRequest) bool {
	conditions := policy.Spec.Conditions

	if len(conditions.Accounts) > 0 {
		matched := false
		for _, account := range conditions.Accounts {
			if account == req.Spec.AWSAccount {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check clusters
	if len(conditions.Clusters) > 0 {
		matched := false
		for _, cluster := range conditions.Clusters {
			if cluster == req.Spec.EKSCluster {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check access policies
	if len(conditions.AccessPolicies) > 0 {
		matched := false
		for _, accessPolicy := range conditions.AccessPolicies {
			if accessPolicy == req.Spec.AccessPolicy {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check IAM role patterns
	if len(conditions.IAMRolePatterns) > 0 {
		matched := false
		for _, pattern := range conditions.IAMRolePatterns {
			if matched, _ := regexp.MatchString(pattern, req.Spec.IAMRole); matched {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check requester patterns
	if len(conditions.RequesterPatterns) > 0 {
		matched := false
		for _, pattern := range conditions.RequesterPatterns {
			if matched, _ := regexp.MatchString(pattern, req.Spec.Requestor); matched {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check tags
	if len(conditions.Tags) > 0 {
		for key, value := range conditions.Tags {
			if reqValue, ok := req.Spec.Tags[key]; !ok || reqValue != value {
				return false
			}
		}
	}

	return true
}

func (r *EKSAccessRequestReconciler) getApprovalPolicy(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (*accessv1alpha1.ApprovalPolicy, error) {
	policyName, ok := req.Annotations[annotationApprovalPolicy]
	if !ok {
		return nil, fmt.Errorf("approval policy not found in annotations")
	}

	policy := &accessv1alpha1.ApprovalPolicy{}
	if err := r.Get(ctx, k8stypes.NamespacedName{Name: policyName, Namespace: req.Namespace}, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

func (r *EKSAccessRequestReconciler) countStageApprovals(req *accessv1alpha1.EKSAccessRequest, stage int) (approvals, rejections int) {
	for _, approval := range req.Status.Approvals {
		if approval.Stage == stage {
			if approval.Decision == "approved" {
				approvals++
			} else if approval.Decision == "rejected" {
				rejections++
			}
		}
	}
	return
}

func (r *EKSAccessRequestReconciler) getEKSClient(region string) (*eks.Client, error) {
	if r.eksClients == nil {
		r.eksClients = make(map[string]*eks.Client)
	}

	if client, ok := r.eksClients[region]; ok {
		return client, nil
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	client := eks.NewFromConfig(cfg)
	r.eksClients[region] = client

	return client, nil
}

func (r *EKSAccessRequestReconciler) createEKSAccessEntry(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) error {
	// First, look up the EKSCluster CRD to get the region
	clusterList := &accessv1alpha1.EKSClusterList{}
	if err := r.List(ctx, clusterList, client.InNamespace(req.Namespace)); err != nil {
		return fmt.Errorf("failed to list EKS clusters: %w", err)
	}

	var eksCluster *accessv1alpha1.EKSCluster
	for i := range clusterList.Items {
		cluster := &clusterList.Items[i]
		if cluster.Spec.ClusterName == req.Spec.EKSCluster &&
			cluster.Spec.AccountID == req.Spec.AWSAccount {
			eksCluster = cluster
			break
		}
	}

	if eksCluster == nil {
		return fmt.Errorf("EKS cluster %s not found in account %s",
			req.Spec.EKSCluster, req.Spec.AWSAccount)
	}

	// Use the region from the EKSCluster CRD
	region := eksCluster.Spec.Region
	if region == "" {
		if eksCluster.Spec.ClusterArn != "" {
			region = r.extractRegionFromCluster(eksCluster.Spec.ClusterArn)
		}
		if region == "" {
			region = r.DefaultRegion
		}
	}

	log := r.Log.WithValues("cluster", req.Spec.EKSCluster, "region", region)
	log.Info("Creating EKS access entry")

	eksClient, err := r.getEKSClient(region)
	if err != nil {
		return fmt.Errorf("failed to get EKS client for region %s: %w", region, err)
	}

	policyArn := r.getFullPolicyArn(req.Spec.AccessPolicy)

	// Use the cluster name from the request
	clusterName := req.Spec.EKSCluster

	input := &eks.CreateAccessEntryInput{
		ClusterName:  &clusterName,
		PrincipalArn: &req.Spec.IAMRole,
		Tags:         req.Spec.Tags,
	}

	output, err := eksClient.CreateAccessEntry(ctx, input)
	if err != nil {
		// Check if already exists
		if strings.Contains(err.Error(), "ResourceInUseException") {
			log.Info("Access entry already exists, fetching details")

			// Fetch the existing entry
			describeInput := &eks.DescribeAccessEntryInput{
				ClusterName:  &clusterName,
				PrincipalArn: &req.Spec.IAMRole,
			}

			describeOutput, descErr := eksClient.DescribeAccessEntry(ctx, describeInput)
			if descErr == nil && describeOutput.AccessEntry != nil {
				req.Status.EKSAccessEntryArn = *describeOutput.AccessEntry.AccessEntryArn

				// Still need to associate policy
				policyInput := &eks.AssociateAccessPolicyInput{
					ClusterName:  &clusterName,
					PrincipalArn: &req.Spec.IAMRole,
					PolicyArn:    &policyArn,
					AccessScope: &types.AccessScope{
						Type: types.AccessScopeTypeCluster,
					},
				}

				_, policyErr := eksClient.AssociateAccessPolicy(ctx, policyInput)
				if policyErr != nil && !strings.Contains(policyErr.Error(), "already associated") {
					log.Error(policyErr, "Failed to associate policy")
				}

				return nil // Entry exists, consider it success
			}
		}
		return fmt.Errorf("failed to create access entry: %w", err)
	}

	// Store the ARN
	if output.AccessEntry != nil && output.AccessEntry.AccessEntryArn != nil {
		req.Status.EKSAccessEntryArn = *output.AccessEntry.AccessEntryArn
	}

	// Associate the policy
	policyInput := &eks.AssociateAccessPolicyInput{
		ClusterName:  &clusterName,
		PrincipalArn: &req.Spec.IAMRole,
		PolicyArn:    &policyArn,
		AccessScope: &types.AccessScope{
			Type: types.AccessScopeTypeCluster,
		},
	}

	_, err = eksClient.AssociateAccessPolicy(ctx, policyInput)
	if err != nil {
		if !strings.Contains(err.Error(), "already associated") {
			// Try to delete the access entry if policy association fails
			deleteInput := &eks.DeleteAccessEntryInput{
				ClusterName:  &clusterName,
				PrincipalArn: &req.Spec.IAMRole,
			}
			eksClient.DeleteAccessEntry(ctx, deleteInput)
			return fmt.Errorf("failed to associate access policy: %w", err)
		}
	}

	log.Info("Successfully created EKS access entry", "arn", req.Status.EKSAccessEntryArn)
	return nil
}

func (r *EKSAccessRequestReconciler) deleteEKSAccessEntry(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) error {
	log := r.Log.WithValues("eksaccessrequest", req.Name, "cluster", req.Spec.EKSCluster)

	// Look up the EKSCluster CRD to get the region
	clusterList := &accessv1alpha1.EKSClusterList{}
	if err := r.List(ctx, clusterList, client.InNamespace(req.Namespace)); err != nil {
		log.Error(err, "Failed to list EKS clusters")
		return fmt.Errorf("failed to list EKS clusters: %w", err)
	}

	var eksCluster *accessv1alpha1.EKSCluster
	for i := range clusterList.Items {
		cluster := &clusterList.Items[i]
		if cluster.Spec.ClusterName == req.Spec.EKSCluster &&
			cluster.Spec.AccountID == req.Spec.AWSAccount {
			eksCluster = cluster
			break
		}
	}

	region := r.DefaultRegion
	if eksCluster != nil {
		region = eksCluster.Spec.Region
	}

	if region == "" {
		region = "ap-northeast-2" // fallback
	}

	log.Info("Deleting EKS access entry", "region", region, "principal", req.Spec.IAMRole)

	eksClient, err := r.getEKSClient(region)
	if err != nil {
		return fmt.Errorf("failed to get EKS client for region %s: %w", region, err)
	}

	input := &eks.DeleteAccessEntryInput{
		ClusterName:  &req.Spec.EKSCluster,
		PrincipalArn: &req.Spec.IAMRole,
	}

	_, err = eksClient.DeleteAccessEntry(ctx, input)
	if err != nil {
		// Check if already deleted
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			log.Info("Access entry not found, already deleted")
			return nil
		}
		return fmt.Errorf("failed to delete access entry: %w", err)
	}

	log.Info("Successfully deleted EKS access entry")
	return nil
}

func (r *EKSAccessRequestReconciler) verifyEKSAccessEntry(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (bool, error) {
	// Look up the EKSCluster CRD to get the region
	clusterList := &accessv1alpha1.EKSClusterList{}
	if err := r.List(ctx, clusterList, client.InNamespace(req.Namespace)); err != nil {
		return false, fmt.Errorf("failed to list EKS clusters: %w", err)
	}

	var eksCluster *accessv1alpha1.EKSCluster
	for i := range clusterList.Items {
		cluster := &clusterList.Items[i]
		if cluster.Spec.ClusterName == req.Spec.EKSCluster &&
			cluster.Spec.AccountID == req.Spec.AWSAccount {
			eksCluster = cluster
			break
		}
	}

	if eksCluster == nil {
		return false, fmt.Errorf("EKS cluster %s not found in account %s",
			req.Spec.EKSCluster, req.Spec.AWSAccount)
	}

	region := eksCluster.Spec.Region
	if region == "" {
		region = r.DefaultRegion
	}

	eksClient, err := r.getEKSClient(region)
	if err != nil {
		return false, err
	}

	input := &eks.DescribeAccessEntryInput{
		ClusterName:  &req.Spec.EKSCluster,
		PrincipalArn: &req.Spec.IAMRole,
	}

	_, err = eksClient.DescribeAccessEntry(ctx, input)
	if err != nil {
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (r *EKSAccessRequestReconciler) getFullPolicyArn(policy string) string {
	policyMap := map[string]string{
		"AmazonEKSViewPolicy":         "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
		"AmazonEKSEditPolicy":         "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy",
		"AmazonEKSAdminPolicy":        "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy",
		"AmazonEKSClusterAdminPolicy": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
	}

	if arn, ok := policyMap[policy]; ok {
		return arn
	}
	return policy
}

func (r *EKSAccessRequestReconciler) extractRegionFromCluster(cluster string) string {
	// If cluster is an ARN, extract region
	// arn:aws:eks:us-west-2:123456789012:cluster/my-cluster
	if strings.HasPrefix(cluster, "arn:aws:eks:") {
		parts := strings.Split(cluster, ":")
		if len(parts) >= 4 {
			return parts[3]
		}
	}
	return ""
}

func (r *EKSAccessRequestReconciler) updateStatus(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	now := metav1.Now()
	req.Status.LastTransitionTime = &now

	if err := r.Status().Update(ctx, req); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *EKSAccessRequestReconciler) transitionToFailed(ctx context.Context, req *accessv1alpha1.EKSAccessRequest, message string) (ctrl.Result, error) {
	req.Status.State = accessv1alpha1.StateFailed
	req.Status.Message = message
	r.Recorder.Event(req, corev1.EventTypeWarning, "Failed", message)
	return r.updateStatus(ctx, req)
}

func isRetryableError(err error) bool {
	// Add logic to determine if error is retryable
	errorStr := err.Error()
	retryableErrors := []string{
		"Throttling",
		"ServiceUnavailable",
		"RequestTimeout",
		"TooManyRequests",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(errorStr, retryable) {
			return true
		}
	}

	return false
}

func (r *EKSAccessRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("eksaccessrequest-controller").
		For(&accessv1alpha1.EKSAccessRequest{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
		}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				// Always process new requests
				return true
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				oldReq := e.ObjectOld.(*accessv1alpha1.EKSAccessRequest)
				newReq := e.ObjectNew.(*accessv1alpha1.EKSAccessRequest)

				// Always reconcile if spec changed
				if !reflect.DeepEqual(oldReq.Spec, newReq.Spec) {
					return true
				}

				// Always reconcile if state changed
				if oldReq.Status.State != newReq.Status.State {
					return true
				}

				// Always reconcile if approvals were added
				if len(oldReq.Status.Approvals) != len(newReq.Status.Approvals) {
					return true
				}

				// Always reconcile if the approval/rejection annotations changed
				// This catches updates from ApproveRequest/RejectRequest
				oldApproval := oldReq.Annotations["eksaccess.io/last-approval"]
				newApproval := newReq.Annotations["eksaccess.io/last-approval"]
				if oldApproval != newApproval {
					return true
				}

				oldRejection := oldReq.Annotations["eksaccess.io/last-rejection"]
				newRejection := newReq.Annotations["eksaccess.io/last-rejection"]
				if oldRejection != newRejection {
					return true
				}

				// Don't reconcile for other status-only updates
				return false
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				// Process deletions for cleanup
				return true
			},
			GenericFunc: func(e event.GenericEvent) bool {
				// Process generic events
				return true
			},
		}).
		Complete(r)
}

//func (r *EKSAccessRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
//	return ctrl.NewControllerManagedBy(mgr).
//		Named("eksaccessrequest-controller").
//		For(&accessv1alpha1.EKSAccessRequest{}).
//		WithOptions(controller.Options{
//			MaxConcurrentReconciles: 3,
//		}).
//		WithEventFilter(predicate.Funcs{
//			UpdateFunc: func(e event.UpdateEvent) bool {
//				// Only reconcile if spec changed or if state transition is needed
//				oldReq := e.ObjectOld.(*accessv1alpha1.EKSAccessRequest)
//				newReq := e.ObjectNew.(*accessv1alpha1.EKSAccessRequest)
//
//				// Reconcile if spec changed
//				if !reflect.DeepEqual(oldReq.Spec, newReq.Spec) {
//					return true
//				}
//
//				// Reconcile if state changed (but not other status fields)
//				if oldReq.Status.State != newReq.Status.State {
//					return true
//				}
//
//				// Don't reconcile for other status updates (like adding approvals)
//				return false
//			},
//		}).
//		Complete(r)
//}
