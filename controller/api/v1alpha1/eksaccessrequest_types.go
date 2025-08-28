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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EKSAccessRequestSpec defines the desired state of EKSAccessRequest
type EKSAccessRequestSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	Requestor string `json:"requestor"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$`
	IAMRole string `json:"iamRole"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^\d{12}$`
	AWSAccount string `json:"awsAccount"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=100
	EKSCluster string `json:"eksCluster"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=AmazonEKSViewPolicy;AmazonEKSEditPolicy;AmazonEKSAdminPolicy;AmazonEKSClusterAdminPolicy
	AccessPolicy string `json:"accessPolicy"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=10
	// +kubebuilder:validation:MaxLength=500
	Reason string `json:"reason"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Format=date-time
	ExpirationTime *metav1.Time `json:"expirationTime,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=default
	ApprovalPolicy string `json:"approvalPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	Tags map[string]string `json:"tags,omitempty"`
}

// AccessRequestState represents the state of an access request
// +kubebuilder:validation:Enum=pending;awaiting-approval;approved;rejected;provisioning;active;expired;revoked;failed
type AccessRequestState string

const (
	StatePending          AccessRequestState = "pending"
	StateAwaitingApproval AccessRequestState = "awaiting-approval"
	StateApproved         AccessRequestState = "approved"
	StateRejected         AccessRequestState = "rejected"
	StateProvisioning     AccessRequestState = "provisioning"
	StateActive           AccessRequestState = "active"
	StateExpired          AccessRequestState = "expired"
	StateRevoked          AccessRequestState = "revoked"
	StateFailed           AccessRequestState = "failed"
)

// Approval represents an approval decision
type Approval struct {
	// +kubebuilder:validation:Required
	Stage int `json:"stage"`

	// +kubebuilder:validation:Required
	Approver string `json:"approver"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=approved;rejected
	Decision string `json:"decision"`

	// +kubebuilder:validation:Required
	Timestamp metav1.Time `json:"timestamp"`

	// +kubebuilder:validation:Optional
	Comment string `json:"comment,omitempty"`
}

// SlackMessageInfo stores Slack message metadata
type SlackMessageInfo struct {
	ChannelID string `json:"channelId,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	UserID    string `json:"userId,omitempty"`
}

// EKSAccessRequestStatus defines the observed state of EKSAccessRequest
type EKSAccessRequestStatus struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=pending
	State AccessRequestState `json:"state,omitempty"`

	// +kubebuilder:validation:Optional
	Approvals []Approval `json:"approvals,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=0
	CurrentStage int `json:"currentStage,omitempty"`

	// +kubebuilder:validation:Optional
	EKSAccessEntryArn string `json:"eksAccessEntryArn,omitempty"`

	// +kubebuilder:validation:Optional
	Message string `json:"message,omitempty"`

	// +kubebuilder:validation:Optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// +kubebuilder:validation:Optional
	SlackMessages map[string]SlackMessageInfo `json:"slackMessages,omitempty"`

	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ear
// +kubebuilder:printcolumn:name="Requestor",type=string,JSONPath=`.spec.requestor`
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.eksCluster`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// EKSAccessRequest is the Schema for the eksaccessrequests API
type EKSAccessRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EKSAccessRequestSpec   `json:"spec,omitempty"`
	Status EKSAccessRequestStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EKSAccessRequestList contains a list of EKSAccessRequest
type EKSAccessRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EKSAccessRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EKSAccessRequest{}, &EKSAccessRequestList{})
}
