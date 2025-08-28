package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	accessv1alpha1 "eks-access-slack/controller/api/v1alpha1"
	"eks-access-slack/slack-bot/pkg/k8sclient"
	"eks-access-slack/slack-bot/pkg/slackclient"
)

type Handler struct {
	slackClient       *slackclient.Client
	slackAPI          *slack.Client
	k8sClient         *k8sclient.K8sClient
	notificationQueue chan accessv1alpha1.NotificationEvent
}

func NewHandler(slackClient *slackclient.Client, k8sClient *k8sclient.K8sClient, queue chan accessv1alpha1.NotificationEvent) *Handler {
	return &Handler{
		slackClient:       slackClient,
		slackAPI:          slackClient.GetAPI(),
		k8sClient:         k8sClient,
		notificationQueue: queue,
	}
}

// ConsumeNotifications processes notifications from the Kubernetes controller
func (h *Handler) ConsumeNotifications(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case notification := <-h.notificationQueue:
			if err := h.processNotification(notification); err != nil {
				logrus.Errorf("Failed to process notification: %v", err)
			}
		}
	}
}

func (h *Handler) processNotification(notification accessv1alpha1.NotificationEvent) error {
	switch notification.Type {
	case "approval_required":
		return h.sendApprovalRequests(notification)
	case "request_approved":
		return h.sendApprovalConfirmation(notification)
	case "request_rejected":
		return h.sendRejectionNotification(notification)
	case "access_active":
		return h.sendActivationNotification(notification)
	case "access_terminated":
		return h.sendTerminationNotification(notification)
	default:
		return fmt.Errorf("unknown notification type: %s", notification.Type)
	}
}

func (h *Handler) sendApprovalRequests(notification accessv1alpha1.NotificationEvent) error {
	req := notification.Request
	stage := notification.Stage

	blocks := h.buildApprovalMessageBlocks(req, stage)

	for _, approverEmail := range notification.Approvers {
		user, err := h.slackClient.GetUserByEmail(approverEmail)
		if err != nil {
			logrus.Errorf("Failed to find Slack user for %s: %v", approverEmail, err)
			continue
		}

		channel, _, _, err := h.slackClient.OpenConversation(&slack.OpenConversationParameters{
			Users: []string{user.ID},
		})
		if err != nil {
			logrus.Errorf("Failed to open DM with %s: %v", approverEmail, err)
			continue
		}

		_, timestamp, err := h.slackClient.PostMessage(
			channel.ID,
			slack.MsgOptionBlocks(blocks...),
			slack.MsgOptionText(fmt.Sprintf("Approval required for EKS access request from %s", req.Spec.Requestor), false),
		)
		if err != nil {
			logrus.Errorf("Failed to send message to %s: %v", approverEmail, err)
			continue
		}

		messageKey := fmt.Sprintf("stage-%d-%s", stage, approverEmail)
		h.k8sClient.UpdateSlackMessageMetadata(
			context.Background(),
			req.Name,
			messageKey,
			accessv1alpha1.SlackMessageInfo{
				ChannelID: channel.ID,
				Timestamp: timestamp,
				UserID:    user.ID,
			},
		)
	}

	return nil
}

func (h *Handler) buildApprovalMessageBlocks(req *accessv1alpha1.EKSAccessRequest, stage int) []slack.Block {
	headerText := fmt.Sprintf(
		"*Access Request Approval Required*\n"+
			"Requestor: %s\n"+
			"Cluster: `%s`\n"+
			"Access Policy: `%s`\n"+
			"Reason: %s\n"+
			"Stage: %d",
		req.Spec.Requestor,
		req.Spec.EKSCluster,
		req.Spec.AccessPolicy,
		req.Spec.Reason,
		stage,
	)

	blocks := []slack.Block{
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", headerText, false, false),
			nil, nil,
		),
	}

	if req.Spec.ExpirationTime != nil {
		expirationText := fmt.Sprintf("*Expires:* %s", req.Spec.ExpirationTime.Format(time.RFC3339))
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", expirationText, false, false),
			nil, nil,
		))
	}

	approveBtn := slack.NewButtonBlockElement(
		"approve_request",
		req.Name,
		slack.NewTextBlockObject("plain_text", "Approve", false, false),
	).WithStyle(slack.StylePrimary)

	rejectBtn := slack.NewButtonBlockElement(
		"reject_request",
		req.Name,
		slack.NewTextBlockObject("plain_text", "Reject", false, false),
	).WithStyle(slack.StyleDanger)

	blocks = append(blocks, slack.NewActionBlock(
		"",
		approveBtn,
		rejectBtn,
	))

	return blocks
}

func (h *Handler) sendApprovalConfirmation(notification accessv1alpha1.NotificationEvent) error {
	req := notification.Request

	user, err := h.slackClient.GetUserByEmail(req.Spec.Requestor)
	if err != nil {
		logrus.Errorf("Failed to find Slack user for requestor %s: %v", req.Spec.Requestor, err)
		return err
	}

	channel, _, _, err := h.slackClient.OpenConversation(&slack.OpenConversationParameters{
		Users: []string{user.ID},
	})
	if err != nil {
		logrus.Errorf("Failed to open DM with requestor: %v", err)
		return err
	}

	message := fmt.Sprintf(
		"*Access Request Approved*\n"+
			"Your EKS access request has been approved!\n"+
			"Cluster: `%s`\n"+
			"Access Policy: `%s`\n"+
			"Your access will be provisioned shortly.",
		req.Spec.EKSCluster,
		req.Spec.AccessPolicy,
	)

	_, _, err = h.slackClient.PostMessage(
		channel.ID,
		slack.MsgOptionText(message, false),
	)
	return err
}

func (h *Handler) sendRejectionNotification(notification accessv1alpha1.NotificationEvent) error {
	req := notification.Request

	user, err := h.slackClient.GetUserByEmail(req.Spec.Requestor)
	if err != nil {
		logrus.Errorf("Failed to find Slack user for requestor %s: %v", req.Spec.Requestor, err)
		return err
	}

	channel, _, _, err := h.slackClient.OpenConversation(&slack.OpenConversationParameters{
		Users: []string{user.ID},
	})
	if err != nil {
		logrus.Errorf("Failed to open DM with requestor: %v", err)
		return err
	}

	message := fmt.Sprintf(
		"*Access Request Rejected*\n"+
			"Your EKS access request has been rejected.\n"+
			"Cluster: `%s`\n"+
			"Access Policy: `%s`\n"+
			"Please contact the approver for more details.",
		req.Spec.EKSCluster,
		req.Spec.AccessPolicy,
	)

	_, _, err = h.slackClient.PostMessage(
		channel.ID,
		slack.MsgOptionText(message, false),
	)
	return err
}

func (h *Handler) sendActivationNotification(notification accessv1alpha1.NotificationEvent) error {
	req := notification.Request

	user, err := h.slackClient.GetUserByEmail(req.Spec.Requestor)
	if err != nil {
		logrus.Errorf("Failed to find Slack user for requestor %s: %v", req.Spec.Requestor, err)
		return err
	}

	channel, _, _, err := h.slackClient.OpenConversation(&slack.OpenConversationParameters{
		Users: []string{user.ID},
	})
	if err != nil {
		logrus.Errorf("Failed to open DM with requestor: %v", err)
		return err
	}

	message := fmt.Sprintf(
		"*EKS Access Active*\n"+
			"Your EKS access is now active!\n"+
			"Cluster: `%s`\n"+
			"Access Policy: `%s`\n"+
			"Access Entry ARN: `%s`\n"+
			"You can now access the cluster using your configured AWS credentials.",
		req.Spec.EKSCluster,
		req.Spec.AccessPolicy,
		req.Status.EKSAccessEntryArn,
	)

	_, _, err = h.slackClient.PostMessage(
		channel.ID,
		slack.MsgOptionText(message, false),
	)
	return err
}

func (h *Handler) sendTerminationNotification(notification accessv1alpha1.NotificationEvent) error {
	req := notification.Request

	user, err := h.slackClient.GetUserByEmail(req.Spec.Requestor)
	if err != nil {
		logrus.Errorf("Failed to find Slack user for requestor %s: %v", req.Spec.Requestor, err)
		return err
	}

	channel, _, _, err := h.slackClient.OpenConversation(&slack.OpenConversationParameters{
		Users: []string{user.ID},
	})
	if err != nil {
		logrus.Errorf("Failed to open DM with requestor: %v", err)
		return err
	}

	message := fmt.Sprintf(
		"*EKS Access Terminated*\n"+
			"Your EKS access has been terminated.\n"+
			"Cluster: `%s`\n"+
			"Access Policy: `%s`\n"+
			"Reason: %s",
		req.Spec.EKSCluster,
		req.Spec.AccessPolicy,
		req.Status.Message,
	)

	_, _, err = h.slackClient.PostMessage(
		channel.ID,
		slack.MsgOptionText(message, false),
	)
	return err
}

func (h *Handler) HandleInteractive(evt *socketmode.Event, client *socketmode.Client) {
	callback, ok := evt.Data.(slack.InteractionCallback)
	if !ok {
		logrus.Error("Failed to parse interaction callback")
		client.Ack(*evt.Request)
		return
	}

	switch callback.Type {
	case slack.InteractionTypeBlockActions:
		h.handleBlockActions(callback, client, evt)
	case slack.InteractionTypeViewSubmission:
		h.handleViewSubmission(callback, client, evt)
	default:
		client.Ack(*evt.Request)
	}
}

func (h *Handler) handleBlockActions(callback slack.InteractionCallback, client *socketmode.Client, evt *socketmode.Event) {
	for _, action := range callback.ActionCallback.BlockActions {
		switch action.ActionID {
		case "approve_request":
			h.handleApproval(callback, action.Value, true)
		case "reject_request":
			h.handleApproval(callback, action.Value, false)
		}
	}
	client.Ack(*evt.Request)
}

func (h *Handler) handleApproval(callback slack.InteractionCallback, requestName string, approve bool) {
	ctx := context.Background()

	logrus.Infof("Processing approval decision: request=%s, approve=%v, user=%s",
		requestName, approve, callback.User.ID)

	request, err := h.k8sClient.GetAccessRequest(ctx, requestName)
	if err != nil {
		logrus.Errorf("Failed to get request %s: %v", requestName, err)
		h.sendErrorMessage(callback.Channel.ID, callback.User.ID,
			fmt.Sprintf("Failed to find request: %v", err))
		return
	}

	currentState := string(request.Status.State)
	logrus.Infof("Request %s current state: %s", requestName, currentState)

	if currentState != "awaiting-approval" && currentState != "pending" {
		logrus.Errorf("Request %s cannot be processed in state: %s", requestName, currentState)
		h.sendErrorMessage(callback.Channel.ID, callback.User.ID,
			fmt.Sprintf("Request cannot be processed in current state: %s", currentState))
		return
	}

	approverEmail := ""

	if callback.User.Profile.Email != "" {
		approverEmail = callback.User.Profile.Email
		logrus.Infof("Got email from callback profile: %s", approverEmail)
	}

	if approverEmail == "" && callback.User.Name != "" {
		if strings.Contains(callback.User.Name, "@") {
			approverEmail = callback.User.Name
			logrus.Infof("Got email from user name field: %s", approverEmail)
		}
	}

	if approverEmail == "" {
		logrus.Infof("Fetching user info from Slack API for user %s", callback.User.ID)
		user, err := h.slackAPI.GetUserInfo(callback.User.ID)
		if err != nil {
			logrus.Errorf("Failed to get user info from Slack: %v", err)
		} else if user != nil {
			approverEmail = user.Profile.Email
			if approverEmail == "" {
				logrus.Warnf("User profile email is empty for user %s", callback.User.ID)
				if user.Profile.RealName != "" {
					approverEmail = user.Profile.RealName
					logrus.Infof("Using real name as email: %s", approverEmail)
				}
			} else {
				logrus.Infof("Got email from Slack API: %s", approverEmail)
			}
		}
	}

	if approverEmail == "" {
		approverEmail = fmt.Sprintf("%s@slack", callback.User.ID)
		logrus.Warnf("Could not get email, using fallback: %s", approverEmail)

		h.sendErrorMessage(callback.Channel.ID, callback.User.ID,
			"Warning: Could not retrieve your email. Using Slack ID as identifier.")
	}

	logrus.Infof("Final approver email: %s", approverEmail)

	var processErr error
	if approve {
		logrus.Infof("Approving request %s by %s", requestName, approverEmail)
		processErr = h.k8sClient.ApproveRequest(ctx, requestName, approverEmail, "Approved via Slack")
	} else {
		logrus.Infof("Rejecting request %s by %s", requestName, approverEmail)
		processErr = h.k8sClient.RejectRequest(ctx, requestName, approverEmail, "Rejected via Slack")
	}

	if processErr != nil {
		logrus.Errorf("Failed to process %s decision for request %s: %v",
			map[bool]string{true: "approval", false: "rejection"}[approve],
			requestName, processErr)

		h.sendErrorMessage(callback.Channel.ID, callback.User.ID,
			fmt.Sprintf("Failed to process %s: %v",
				map[bool]string{true: "approval", false: "rejection"}[approve],
				processErr))
		return
	}

	if approve {
		h.updateApprovalMessage(callback, "approved")
		logrus.Infof("Successfully approved request %s", requestName)
	} else {
		h.updateApprovalMessage(callback, "rejected")
		logrus.Infof("Successfully rejected request %s", requestName)
	}
}

func (h *Handler) updateApprovalMessage(callback slack.InteractionCallback, decision string) {
	statusText := fmt.Sprintf("*Status:* You have %s this request", decision)

	blocks := callback.Message.Blocks.BlockSet
	if len(blocks) > 0 && blocks[len(blocks)-1].BlockType() == slack.MBTAction {
		blocks = blocks[:len(blocks)-1]
	}

	blocks = append(blocks, slack.NewSectionBlock(
		slack.NewTextBlockObject("mrkdwn", statusText, false, false),
		nil, nil,
	))

	h.slackAPI.UpdateMessage(
		callback.Channel.ID,
		callback.Message.Timestamp,
		slack.MsgOptionBlocks(blocks...),
	)
}

func (h *Handler) sendErrorMessage(channelID, userID, message string) {
	h.slackAPI.PostEphemeral(
		channelID,
		userID,
		slack.MsgOptionText(message, false),
	)
}

// Helper function to send error messages
func (h *Handler) sendErrorResponse(channelID, userID, message string) {
	_, err := h.slackAPI.PostEphemeral(
		channelID,
		userID,
		slack.MsgOptionText(message, false),
	)
	if err != nil {
		logrus.Errorf("Failed to send error message: %v", err)
	}
}

func (h *Handler) handleViewSubmission(callback slack.InteractionCallback, client *socketmode.Client, evt *socketmode.Event) {
	logrus.Infof("Processing view submission from user %s", callback.User.ID)

	values := callback.View.State.Values

	awsAccount := values["aws_account_select"]["aws_account_select"].SelectedOption.Value
	iamRole := values["iam_role_select"]["iam_role_select"].SelectedOption.Value
	eksCluster := values["eks_cluster_select"]["eks_cluster_select"].SelectedOption.Value
	accessPolicy := values["access_policy_select"]["access_policy_select"].SelectedOption.Value
	duration := values["duration_select"]["duration_select"].SelectedOption.Value
	reason := values["reason"]["reason"].Value

	if awsAccount == "" || iamRole == "" || eksCluster == "" || reason == "" {
		logrus.Error("Missing required fields in modal submission")
		client.Ack(*evt.Request, map[string]interface{}{
			"response_action": "errors",
			"errors": map[string]string{
				"reason": "All fields are required",
			},
		})
		return
	}

	user, err := h.slackAPI.GetUserInfo(callback.User.ID)
	if err != nil {
		logrus.Errorf("Failed to get user info: %v", err)
		client.Ack(*evt.Request, map[string]interface{}{
			"response_action": "errors",
			"errors": map[string]string{
				"reason": "Failed to get user information. Please try again.",
			},
		})
		return
	}

	input := &k8sclient.AccessRequestInput{
		RequestorEmail: user.Profile.Email,
		SlackUserID:    callback.User.ID,
		SlackChannelID: callback.Channel.ID,
		IAMRole:        iamRole,
		AWSAccount:     awsAccount,
		Cluster:        eksCluster,
		AccessPolicy:   accessPolicy,
		Reason:         reason,
		Duration:       duration,
	}

	logrus.Infof("Creating access request: AWS Account=%s, Cluster=%s, Role=%s", awsAccount, eksCluster, iamRole)

	ctx := context.Background()
	request, err := h.k8sClient.CreateAccessRequest(ctx, input)
	if err != nil {
		logrus.Errorf("Failed to create access request: %v", err)
		client.Ack(*evt.Request, map[string]interface{}{
			"response_action": "errors",
			"errors": map[string]string{
				"reason": fmt.Sprintf("Failed to create access request: %v", err),
			},
		})
		return
	}

	client.Ack(*evt.Request)

	successMsg := fmt.Sprintf(
		"*EKS Access Request Submitted Successfully!*\n\n"+
			"*Request ID:* `%s`\n"+
			"*AWS Account:* `%s`\n"+
			"*Cluster:* `%s`\n"+
			"*IAM Role:* `%s`\n"+
			"*Access Level:* `%s`\n"+
			"*Duration:* `%s`\n"+
			"*Reason:* _%s_\n\n"+
			"Your request has been submitted for approval. You'll be notified when it's processed.",
		request.Name,
		awsAccount,
		eksCluster,
		iamRole,
		accessPolicy,
		duration,
		reason,
	)

	channel, _, _, err := h.slackAPI.OpenConversation(&slack.OpenConversationParameters{
		Users: []string{callback.User.ID},
	})
	if err != nil {
		logrus.Errorf("Failed to open DM with user: %v", err)
		return
	}

	_, _, err = h.slackAPI.PostMessage(
		channel.ID,
		slack.MsgOptionText(successMsg, false),
	)
	if err != nil {
		logrus.Errorf("Failed to send success message: %v", err)
	}
}

// HandleEvents handles Slack events for webhook mode
func (h *Handler) HandleEvents(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}

// HandleSlashCommand handles Slack slash commands using modal dialogs
func (h *Handler) HandleSlashCommand(evt *socketmode.Event, client *socketmode.Client) {
	logrus.Infof("Received slash command event")

	if evt.Request == nil {
		logrus.Error("Event request is nil, cannot acknowledge")
		return
	}

	cmd, ok := evt.Data.(slack.SlashCommand)
	if !ok {
		logrus.Errorf("Failed to parse slash command data: %+v", evt.Data)
		client.Ack(*evt.Request)
		return
	}

	logrus.Infof("Processing command: %s from user %s", cmd.Command, cmd.UserID)

	switch cmd.Command {
	case "/request-eks":
		h.openAWSAccessModal(cmd)
	default:
		logrus.Warnf("Unknown slash command: %s", cmd.Command)
	}

	client.Ack(*evt.Request)
}

// openAWSAccessModal opens a modal dialog for AWS access request
func (h *Handler) openAWSAccessModal(cmd slack.SlashCommand) {
	logrus.Infof("Opening AWS access modal for user %s", cmd.UserID)

	user, err := h.slackAPI.GetUserInfo(cmd.UserID)
	if err != nil {
		logrus.Errorf("Failed to get user info: %v", err)
		h.sendErrorResponse(cmd.ChannelID, cmd.UserID,
			"Failed to get user information. Please try again.")
		return
	}

	ctx := context.Background()

	resourceOptions, err := h.k8sClient.GetResourceOptionsForUser(ctx, user.Profile.Email)
	if err != nil {
		logrus.Errorf("Failed to fetch resource options: %v", err)
		h.sendErrorResponse(cmd.ChannelID, cmd.UserID,
			"Failed to load available resources. Please try again.")
		return
	}

	if len(resourceOptions.Accounts) == 0 {
		h.sendErrorResponse(cmd.ChannelID, cmd.UserID,
			"No AWS accounts are configured. Please contact your administrator.")
		return
	}

	modalRequest := h.generateEKSAccessModalRequest(resourceOptions)
	view, err := h.slackAPI.OpenView(cmd.TriggerID, modalRequest)

	logrus.Infof("Modal view opened: %+v, Error: %+v", view, err)

	if err != nil {
		logrus.Errorf("Error opening modal view: %v", err)
		h.sendErrorResponse(cmd.ChannelID, cmd.UserID,
			"Failed to open request form. Please try again.")
	}
}

// generateEKSAccessModalRequest creates a modal for EKS access requests with dropdowns
func (h *Handler) generateEKSAccessModalRequest(resources *k8sclient.ResourceOptions) slack.ModalViewRequest {
	// Create modal title, close and submit buttons
	titleText := slack.NewTextBlockObject(slack.PlainTextType, "Request EKS Access", true, false)
	closeText := slack.NewTextBlockObject(slack.PlainTextType, "Cancel", true, false)
	submitText := slack.NewTextBlockObject(slack.PlainTextType, "Submit Request", true, false)

	var accountOptions []*slack.OptionBlockObject
	for _, account := range resources.Accounts {
		label := fmt.Sprintf("%s (%s)", account.Spec.Name, account.Spec.AccountID)
		if account.Spec.Environment != "" {
			label = fmt.Sprintf("%s - %s", label, account.Spec.Environment)
		}
		accountOptions = append(accountOptions, &slack.OptionBlockObject{
			Text:  slack.NewTextBlockObject(slack.PlainTextType, label, true, false),
			Value: account.Spec.AccountID,
		})
	}

	accountSelect := &slack.SelectBlockElement{
		Type:        slack.OptTypeStatic,
		Placeholder: slack.NewTextBlockObject(slack.PlainTextType, "Select AWS Account", true, false),
		ActionID:    "aws_account_select",
		Options:     accountOptions,
	}

	// Create IAM Role dropdown - will show all available roles across accounts
	var roleOptions []*slack.OptionBlockObject
	for accountID, roles := range resources.IAMRoles {
		for _, role := range roles {
			// Find account name
			accountName := accountID
			for _, acc := range resources.Accounts {
				if acc.Spec.AccountID == accountID {
					accountName = acc.Spec.Name
					break
				}
			}

			label := fmt.Sprintf("%s (%s)", role.Spec.DisplayName, accountName)
			if role.Spec.RoleType != "" {
				label = fmt.Sprintf("%s [%s]", label, role.Spec.RoleType)
			}

			// Store role ARN as value
			roleOptions = append(roleOptions, &slack.OptionBlockObject{
				Text:  slack.NewTextBlockObject(slack.PlainTextType, label, true, false),
				Value: role.Spec.RoleArn,
			})
		}
	}

	if len(roleOptions) == 0 {
		// Add a placeholder option if no roles available
		roleOptions = append(roleOptions, &slack.OptionBlockObject{
			Text:  slack.NewTextBlockObject(slack.PlainTextType, "No roles available", true, false),
			Value: "none",
		})
	}

	roleSelect := &slack.SelectBlockElement{
		Type:        slack.OptTypeStatic,
		Placeholder: slack.NewTextBlockObject(slack.PlainTextType, "Select IAM Role", true, false),
		ActionID:    "iam_role_select",
		Options:     roleOptions,
	}

	// Create EKS Cluster dropdown
	var clusterOptions []*slack.OptionBlockObject
	for accountID, clusters := range resources.EKSClusters {
		for _, cluster := range clusters {
			// Find account name
			accountName := accountID
			for _, acc := range resources.Accounts {
				if acc.Spec.AccountID == accountID {
					accountName = acc.Spec.Name
					break
				}
			}

			label := fmt.Sprintf("%s (%s - %s)", cluster.Spec.ClusterName, accountName, cluster.Spec.Region)
			if cluster.Spec.Environment != "" {
				label = fmt.Sprintf("%s [%s]", label, strings.ToUpper(cluster.Spec.Environment))
			}

			clusterOptions = append(clusterOptions, &slack.OptionBlockObject{
				Text:  slack.NewTextBlockObject(slack.PlainTextType, label, true, false),
				Value: cluster.Spec.ClusterName,
			})
		}
	}

	if len(clusterOptions) == 0 {
		// Add a placeholder option if no clusters available
		clusterOptions = append(clusterOptions, &slack.OptionBlockObject{
			Text:  slack.NewTextBlockObject(slack.PlainTextType, "No clusters available", true, false),
			Value: "none",
		})
	}

	clusterSelect := &slack.SelectBlockElement{
		Type:        slack.OptTypeStatic,
		Placeholder: slack.NewTextBlockObject(slack.PlainTextType, "Select EKS Cluster", true, false),
		ActionID:    "eks_cluster_select",
		Options:     clusterOptions,
	}

	// Create Access Policy dropdown with default options
	accessPolicyOptions := []*slack.OptionBlockObject{
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "View Only (AmazonEKSViewPolicy)", true, false), Value: "AmazonEKSViewPolicy"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "Edit (AmazonEKSEditPolicy)", true, false), Value: "AmazonEKSEditPolicy"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "Admin (AmazonEKSAdminPolicy)", true, false), Value: "AmazonEKSAdminPolicy"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "Cluster Admin (AmazonEKSClusterAdminPolicy)", true, false), Value: "AmazonEKSClusterAdminPolicy"},
	}

	accessPolicySelect := &slack.SelectBlockElement{
		Type:        slack.OptTypeStatic,
		Placeholder: slack.NewTextBlockObject(slack.PlainTextType, "Select access level", true, false),
		ActionID:    "access_policy_select",
		Options:     accessPolicyOptions,
		InitialOption: &slack.OptionBlockObject{
			Text:  slack.NewTextBlockObject(slack.PlainTextType, "View Only (AmazonEKSViewPolicy)", true, false),
			Value: "AmazonEKSViewPolicy",
		},
	}

	// Duration select
	durationOptions := []*slack.OptionBlockObject{
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "1 hour", true, false), Value: "1h"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "2 hours", true, false), Value: "2h"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "4 hours", true, false), Value: "4h"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "8 hours", true, false), Value: "8h"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "24 hours", true, false), Value: "24h"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "3 days", true, false), Value: "72h"},
		{Text: slack.NewTextBlockObject(slack.PlainTextType, "7 days", true, false), Value: "168h"},
	}

	durationSelect := &slack.SelectBlockElement{
		Type:        slack.OptTypeStatic,
		Placeholder: slack.NewTextBlockObject(slack.PlainTextType, "Select duration", true, false),
		ActionID:    "duration_select",
		Options:     durationOptions,
		InitialOption: &slack.OptionBlockObject{
			Text:  slack.NewTextBlockObject(slack.PlainTextType, "8 hours", true, false),
			Value: "8h",
		},
	}

	// Reason input
	reasonTextInput := &slack.PlainTextInputBlockElement{
		Type:        slack.METPlainTextInput,
		ActionID:    "reason",
		Placeholder: slack.NewTextBlockObject(slack.PlainTextType, "Please explain why you need access...", true, false),
		Multiline:   true,
	}

	// Store minimal metadata
	metadata := map[string]interface{}{
		"request_type": "eks_access",
	}
	metadataJSON, _ := json.Marshal(metadata)

	// Create blocks
	blocks := slack.Blocks{
		BlockSet: []slack.Block{
			// Add info text if needed
			slack.NewSectionBlock(
				slack.NewTextBlockObject("mrkdwn", "_Select the AWS resources you need access to:_", false, false),
				nil, nil,
			),
			&slack.InputBlock{
				Type:     slack.MBTInput,
				BlockID:  "aws_account_select",
				Label:    slack.NewTextBlockObject(slack.PlainTextType, "AWS Account", true, false),
				Element:  accountSelect,
				Optional: false,
			},
			&slack.InputBlock{
				Type:     slack.MBTInput,
				BlockID:  "iam_role_select",
				Label:    slack.NewTextBlockObject(slack.PlainTextType, "IAM Role", true, false),
				Element:  roleSelect,
				Optional: false,
			},
			&slack.InputBlock{
				Type:     slack.MBTInput,
				BlockID:  "eks_cluster_select",
				Label:    slack.NewTextBlockObject(slack.PlainTextType, "EKS Cluster", true, false),
				Element:  clusterSelect,
				Optional: false,
			},
			&slack.InputBlock{
				Type:     slack.MBTInput,
				BlockID:  "access_policy_select",
				Label:    slack.NewTextBlockObject(slack.PlainTextType, "Access Level", true, false),
				Element:  accessPolicySelect,
				Optional: false,
			},
			&slack.InputBlock{
				Type:     slack.MBTInput,
				BlockID:  "duration_select",
				Label:    slack.NewTextBlockObject(slack.PlainTextType, "Access Duration", true, false),
				Element:  durationSelect,
				Optional: false,
			},
			slack.NewInputBlock("reason", slack.NewTextBlockObject(slack.PlainTextType, "Reason for Access", true, false), nil, reasonTextInput),
		},
	}

	// Create and return modal request
	modalRequest := slack.ModalViewRequest{
		Type:            slack.ViewType("modal"),
		Title:           titleText,
		Close:           closeText,
		Submit:          submitText,
		Blocks:          blocks,
		PrivateMetadata: string(metadataJSON),
	}

	return modalRequest
}
