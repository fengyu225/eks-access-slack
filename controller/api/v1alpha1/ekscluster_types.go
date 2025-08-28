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

// EKSClusterSpec defines the desired state of EKSCluster
type EKSClusterSpec struct {
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=100
	ClusterName string `json:"clusterName"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^\d{12}$`
	AccountID string `json:"accountId"`

	// +kubebuilder:validation:Required
	Region string `json:"region"`

	// +kubebuilder:validation:Optional
	// Full ARN of the cluster if available
	ClusterArn string `json:"clusterArn,omitempty"`

	// +kubebuilder:validation:Optional
	Description string `json:"description,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=production;staging;development;testing
	Environment string `json:"environment,omitempty"`

	// +kubebuilder:validation:Optional
	// Kubernetes version
	Version string `json:"version,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	// List of supported access policies for this cluster
	SupportedAccessPolicies []string `json:"supportedAccessPolicies,omitempty"`

	// +kubebuilder:validation:Optional
	// Default access policy if not specified in request
	DefaultAccessPolicy string `json:"defaultAccessPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	Tags map[string]string `json:"tags,omitempty"`
}

// EKSClusterStatus defines the observed state of EKSCluster
type EKSClusterStatus struct {
	// +kubebuilder:validation:Optional
	ActiveAccessRequests int `json:"activeAccessRequests,omitempty"`

	// +kubebuilder:validation:Optional
	TotalAccessEntries int `json:"totalAccessEntries,omitempty"`

	// +kubebuilder:validation:Optional
	LastUsed *metav1.Time `json:"lastUsed,omitempty"`

	// +kubebuilder:validation:Optional
	// Whether cluster connectivity has been validated
	Validated bool `json:"validated,omitempty"`

	// +kubebuilder:validation:Optional
	// Last time cluster was validated
	LastValidated *metav1.Time `json:"lastValidated,omitempty"`

	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=eksc
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterName`
// +kubebuilder:printcolumn:name="Account-ID",type=string,JSONPath=`.spec.accountId`
// +kubebuilder:printcolumn:name="Region",type=string,JSONPath=`.spec.region`
// +kubebuilder:printcolumn:name="Environment",type=string,JSONPath=`.spec.environment`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// EKSCluster is the Schema for the eksclusters API
type EKSCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EKSClusterSpec   `json:"spec,omitempty"`
	Status EKSClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EKSClusterList contains a list of EKSCluster
type EKSClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EKSCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EKSCluster{}, &EKSClusterList{})
}
