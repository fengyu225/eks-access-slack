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

// NotificationEvent represents a notification event from the Kubernetes controller
type NotificationEvent struct {
	Type        string              `json:"type"`
	Request     *EKSAccessRequest   `json:"request,omitempty"`
	Policy      *ApprovalPolicy     `json:"policy,omitempty"`
	Stage       int                 `json:"stage,omitempty"`
	Approvers   []string            `json:"approvers,omitempty"`
	Action      string              `json:"action,omitempty"`
	SlackUpdate *SlackMessageUpdate `json:"slack_update,omitempty"`
}

// SlackMessageUpdate stores Slack message metadata
type SlackMessageUpdate struct {
	ChannelID string `json:"channel_id"`
	MessageTS string `json:"message_ts"`
	UserID    string `json:"user_id"`
}
