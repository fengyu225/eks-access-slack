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

// ApprovalStage defines a stage in the approval process
type ApprovalStage struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	StageNumber int `json:"stageNumber"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Approvers []string `json:"approvers"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	RequiredApprovals int `json:"requiredApprovals,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AllowSelfApproval bool `json:"allowSelfApproval,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default="24h"
	Timeout string `json:"timeout,omitempty"`

	// +kubebuilder:validation:Optional
	SlackChannels []string `json:"slackChannels,omitempty"`
}

// PolicyCondition defines conditions for when this policy applies
type PolicyCondition struct {
	// +kubebuilder:validation:Optional
	Accounts []string `json:"accounts,omitempty"`

	// +kubebuilder:validation:Optional
	Clusters []string `json:"clusters,omitempty"`

	// +kubebuilder:validation:Optional
	AccessPolicies []string `json:"accessPolicies,omitempty"`

	// +kubebuilder:validation:Optional
	IAMRolePatterns []string `json:"iamRolePatterns,omitempty"`

	// +kubebuilder:validation:Optional
	RequesterPatterns []string `json:"requesterPatterns,omitempty"`

	// +kubebuilder:validation:Optional
	Tags map[string]string `json:"tags,omitempty"`
}

// ApprovalPolicySpec defines the desired state of ApprovalPolicy
type ApprovalPolicySpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Description string `json:"description"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=0
	Priority int `json:"priority,omitempty"`

	// +kubebuilder:validation:Optional
	Conditions PolicyCondition `json:"conditions,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Stages []ApprovalStage `json:"stages"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=false
	AutoApprove bool `json:"autoApprove,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default="168h"
	MaxAccessDuration string `json:"maxAccessDuration,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
}

// ApprovalPolicyStatus defines the observed state of ApprovalPolicy
type ApprovalPolicyStatus struct {
	// +kubebuilder:validation:Optional
	ActiveRequests int `json:"activeRequests,omitempty"`

	// +kubebuilder:validation:Optional
	LastUsed *metav1.Time `json:"lastUsed,omitempty"`

	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ap
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`
// +kubebuilder:printcolumn:name="Stages",type=integer,JSONPath=`.spec.stages[*]`,priority=1
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ApprovalPolicy is the Schema for the approvalpolicies API
type ApprovalPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApprovalPolicySpec   `json:"spec,omitempty"`
	Status ApprovalPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ApprovalPolicyList contains a list of ApprovalPolicy
type ApprovalPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApprovalPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ApprovalPolicy{}, &ApprovalPolicyList{})
}
