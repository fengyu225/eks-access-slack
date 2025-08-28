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

// AWSAccountSpec defines the desired state of AWSAccount
type AWSAccountSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^\d{12}$`
	AccountID string `json:"accountId"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=production;staging;development;testing
	Environment string `json:"environment,omitempty"`

	// +kubebuilder:validation:Optional
	Region string `json:"region,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	Tags map[string]string `json:"tags,omitempty"`
}

// AWSAccountStatus defines the observed state of AWSAccount
type AWSAccountStatus struct {
	// +kubebuilder:validation:Optional
	ActiveAccessRequests int `json:"activeAccessRequests,omitempty"`

	// +kubebuilder:validation:Optional
	LastUsed *metav1.Time `json:"lastUsed,omitempty"`

	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=awsacc
// +kubebuilder:printcolumn:name="Account-ID",type=string,JSONPath=`.spec.accountId`
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Environment",type=string,JSONPath=`.spec.environment`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AWSAccount is the Schema for the awsaccounts API
type AWSAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AWSAccountSpec   `json:"spec,omitempty"`
	Status AWSAccountStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AWSAccountList contains a list of AWSAccount
type AWSAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AWSAccount `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AWSAccount{}, &AWSAccountList{})
}
