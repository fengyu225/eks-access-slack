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
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	accessv1alpha1 "eks-access-slack/controller/api/v1alpha1"
)

const (
	// Annotations for tracking notifications
	annotationNotificationSent     = "eksaccess.io/notification-sent"
	annotationActivationSent       = "eksaccess.io/activation-notified"
	annotationTerminationSent      = "eksaccess.io/termination-notified"
	annotationSlackMessageID       = "eksaccess.io/slack-message-id"
	annotationSlackChannelID       = "eksaccess.io/slack-channel-id"
	annotationSlackThreadTimestamp = "eksaccess.io/slack-thread-ts"
)

// NotificationController handles Slack notifications for access requests
type NotificationController struct {
	client.Client
	Log               logr.Logger
	Scheme            *runtime.Scheme
	NotificationQueue chan accessv1alpha1.NotificationEvent
}

// +kubebuilder:rbac:groups=access.eksaccess.io,resources=eksaccessrequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=access.eksaccess.io,resources=approvalpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *NotificationController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Fetch the EKSAccessRequest
	accessRequest := &accessv1alpha1.EKSAccessRequest{}
	err := r.Get(ctx, req.NamespacedName, accessRequest)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	switch accessRequest.Status.State {
	case accessv1alpha1.StateAwaitingApproval:
		return r.handleApprovalNotification(ctx, accessRequest)
	case accessv1alpha1.StateApproved:
		return r.handleApprovedNotification(ctx, accessRequest)
	case accessv1alpha1.StateRejected:
		return r.handleRejectedNotification(ctx, accessRequest)
	case accessv1alpha1.StateActive:
		return r.handleActiveNotification(ctx, accessRequest)
	case accessv1alpha1.StateExpired, accessv1alpha1.StateRevoked:
		return r.handleTerminationNotification(ctx, accessRequest)
	}

	return ctrl.Result{}, nil
}

func (r *NotificationController) handleApprovalNotification(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	log := r.Log.WithValues("request", req.Name, "stage", req.Status.CurrentStage)

	// Check if notification was already sent
	notifiedStage := req.Annotations[annotationNotifiedStage]
	currentStageStr := fmt.Sprintf("%d", req.Status.CurrentStage)

	if notifiedStage == currentStageStr {
		log.V(1).Info("Notification already sent for this stage")
		return ctrl.Result{}, nil
	}

	// Get the approval policy
	policy, err := r.getApprovalPolicy(ctx, req)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Find current stage
	var currentStage *accessv1alpha1.ApprovalStage
	for _, stage := range policy.Spec.Stages {
		if stage.StageNumber == req.Status.CurrentStage {
			currentStage = &stage
			break
		}
	}

	if currentStage == nil {
		return ctrl.Result{}, fmt.Errorf("stage %d not found in policy", req.Status.CurrentStage)
	}

	// Send notification to shared queue
	notification := accessv1alpha1.NotificationEvent{
		Type:      "approval_required",
		Request:   req.DeepCopy(),
		Policy:    policy,
		Stage:     req.Status.CurrentStage,
		Approvers: currentStage.Approvers,
	}

	// Non-blocking send with timeout
	select {
	case r.NotificationQueue <- notification:
		log.Info("Sent approval notification to queue", "approvers", currentStage.Approvers)
	case <-time.After(5 * time.Second):
		log.Error(nil, "Failed to send notification - queue timeout")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Update annotation to mark as notified
	if req.Annotations == nil {
		req.Annotations = make(map[string]string)
	}
	req.Annotations[annotationNotifiedStage] = currentStageStr

	if err := r.Update(ctx, req); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *NotificationController) handleApprovedNotification(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	notification := accessv1alpha1.NotificationEvent{
		Type:    "request_approved",
		Request: req.DeepCopy(),
		Action:  "approved",
	}

	select {
	case r.NotificationQueue <- notification:
		r.Log.Info("Sent approval notification to requester", "requester", req.Spec.Requestor)
	case <-time.After(5 * time.Second):
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *NotificationController) handleRejectedNotification(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	notification := accessv1alpha1.NotificationEvent{
		Type:    "request_rejected",
		Request: req.DeepCopy(),
		Action:  "rejected",
	}

	select {
	case r.NotificationQueue <- notification:
		r.Log.Info("Sent rejection notification", "requester", req.Spec.Requestor)
	case <-time.After(5 * time.Second):
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *NotificationController) handleActiveNotification(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	if _, ok := req.Annotations[annotationActivationSent]; ok {
		return ctrl.Result{}, nil
	}

	notification := accessv1alpha1.NotificationEvent{
		Type:    "access_active",
		Request: req.DeepCopy(),
		Action:  "activated",
	}

	select {
	case r.NotificationQueue <- notification:
		r.Log.Info("Sent activation notification", "requester", req.Spec.Requestor)

		if req.Annotations == nil {
			req.Annotations = make(map[string]string)
		}
		req.Annotations[annotationActivationSent] = "true"

		if err := r.Update(ctx, req); err != nil {
			return ctrl.Result{}, err
		}
	case <-time.After(5 * time.Second):
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *NotificationController) handleTerminationNotification(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (ctrl.Result, error) {
	if _, ok := req.Annotations[annotationTerminationSent]; ok {
		return ctrl.Result{}, nil
	}

	notification := accessv1alpha1.NotificationEvent{
		Type:    "access_terminated",
		Request: req.DeepCopy(),
		Action:  string(req.Status.State),
	}

	select {
	case r.NotificationQueue <- notification:
		r.Log.Info("Sent termination notification", "requester", req.Spec.Requestor, "state", req.Status.State)

		if req.Annotations == nil {
			req.Annotations = make(map[string]string)
		}
		req.Annotations[annotationTerminationSent] = "true"

		if err := r.Update(ctx, req); err != nil {
			return ctrl.Result{}, err
		}
	case <-time.After(5 * time.Second):
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *NotificationController) getApprovalPolicy(ctx context.Context, req *accessv1alpha1.EKSAccessRequest) (*accessv1alpha1.ApprovalPolicy, error) {
	policyName := req.Annotations[annotationApprovalPolicy]
	if policyName == "" {
		return nil, fmt.Errorf("approval policy not found in annotations")
	}

	policy := &accessv1alpha1.ApprovalPolicy{}
	if err := r.Get(ctx, types.NamespacedName{Name: policyName, Namespace: req.Namespace}, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

func (r *NotificationController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("eksaccessrequest-notification-controller").
		For(&accessv1alpha1.EKSAccessRequest{}).
		WithEventFilter(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
		)).
		Complete(r)
}
