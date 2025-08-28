package slackclient

import (
	"github.com/slack-go/slack"
)

type Client struct {
	api *slack.Client
}

func NewClient(botToken string) *Client {
	return &Client{
		api: slack.New(botToken),
	}
}

// GetUserByEmail retrieves a Slack user by email address
func (c *Client) GetUserByEmail(email string) (*slack.User, error) {
	return c.api.GetUserByEmail(email)
}

// OpenConversation opens a direct message conversation with a user
func (c *Client) OpenConversation(params *slack.OpenConversationParameters) (*slack.Channel, bool, bool, error) {
	return c.api.OpenConversation(params)
}

// PostMessage posts a message to a channel
func (c *Client) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	return c.api.PostMessage(channelID, options...)
}

// UpdateMessage updates an existing message
func (c *Client) UpdateMessage(channelID, timestamp string, options ...slack.MsgOption) (string, string, string, error) {
	return c.api.UpdateMessage(channelID, timestamp, options...)
}

// GetAPI returns the underlying Slack API client
func (c *Client) GetAPI() *slack.Client {
	return c.api
}
