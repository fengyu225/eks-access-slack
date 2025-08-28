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

// IAMRoleSpec defines the desired state of IAMRole
type IAMRoleSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$`
	RoleArn string `json:"roleArn"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	DisplayName string `json:"displayName"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^\d{12}$`
	AccountID string `json:"accountId"`

	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=admin;poweruser;developer;readonly;custom
	RoleType string `json:"roleType,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	// Teams or users allowed to assume this role
	AllowedPrincipals []string `json:"allowedPrincipals,omitempty"`

	// +kubebuilder:validation:Optional
	Tags map[string]string `json:"tags,omitempty"`
}

// IAMRoleStatus defines the observed state of IAMRole
type IAMRoleStatus struct {
	// +kubebuilder:validation:Optional
	ActiveAccessRequests int `json:"activeAccessRequests,omitempty"`

	// +kubebuilder:validation:Optional
	LastUsed *metav1.Time `json:"lastUsed,omitempty"`

	// +kubebuilder:validation:Optional
	Validated bool `json:"validated,omitempty"`

	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=iamr
// +kubebuilder:printcolumn:name="Display-Name",type=string,JSONPath=`.spec.displayName`
// +kubebuilder:printcolumn:name="Account-ID",type=string,JSONPath=`.spec.accountId`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.roleType`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// IAMRole is the Schema for the iamroles API
type IAMRole struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IAMRoleSpec   `json:"spec,omitempty"`
	Status IAMRoleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// IAMRoleList contains a list of IAMRole
type IAMRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IAMRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(&IAMRole{}, &IAMRoleList{})
}
