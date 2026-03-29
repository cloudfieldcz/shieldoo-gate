package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Compile-time interface check.
var _ ChannelSender = (*SlackSender)(nil)

// SlackSender sends alert payloads to a Slack incoming webhook using Block Kit.
type SlackSender struct {
	webhookURL string
	httpClient *http.Client
}

// NewSlackSender creates a SlackSender targeting the given Slack webhook URL.
func NewSlackSender(webhookURL string) *SlackSender {
	return &SlackSender{
		webhookURL: webhookURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Name returns the channel name for metrics and logging.
func (s *SlackSender) Name() string {
	return "slack"
}

// slackMessage is the top-level Slack webhook payload.
type slackMessage struct {
	Blocks []slackBlock `json:"blocks"`
}

// slackBlock represents one block in a Slack Block Kit message.
type slackBlock struct {
	Type     string           `json:"type"`
	Text     *slackTextObj    `json:"text,omitempty"`
	Fields   []slackTextObj   `json:"fields,omitempty"`
	Elements []slackTextObj   `json:"elements,omitempty"`
}

// slackTextObj is a Slack text object (plain_text or mrkdwn).
type slackTextObj struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// eventTitle maps an event type string to a human-readable Slack header title.
func eventTitle(eventType string) string {
	switch eventType {
	case "BLOCKED":
		return "Artifact Blocked"
	case "QUARANTINED":
		return "Artifact Quarantined"
	case "RELEASED":
		return "Artifact Released"
	case "TAG_MUTATED":
		return "Tag Digest Changed"
	case "RESCAN_QUEUED":
		return "Rescan Queued"
	case "OVERRIDE_CREATED":
		return "Override Created"
	case "OVERRIDE_REVOKED":
		return "Override Revoked"
	default:
		return "Security Event: " + eventType
	}
}

// buildSlackMessage constructs a Slack Block Kit message from an AlertPayload.
func buildSlackMessage(payload AlertPayload) slackMessage {
	return slackMessage{
		Blocks: []slackBlock{
			{
				Type: "header",
				Text: &slackTextObj{
					Type: "plain_text",
					Text: eventTitle(payload.EventType),
				},
			},
			{
				Type: "section",
				Fields: []slackTextObj{
					{Type: "mrkdwn", Text: "*Artifact:*\n" + payload.ArtifactID},
					{Type: "mrkdwn", Text: "*Reason:*\n" + payload.Reason},
				},
			},
			{
				Type: "context",
				Elements: []slackTextObj{
					{Type: "mrkdwn", Text: payload.Timestamp.UTC().Format(time.RFC3339)},
				},
			},
		},
	}
}

// Send formats the payload as Slack Block Kit JSON and POSTs it to the webhook.
// Returns HTTPError for 4xx responses (caller should not retry) and a plain
// error for 5xx or other failures.
func (s *SlackSender) Send(ctx context.Context, payload AlertPayload) error {
	msg := buildSlackMessage(payload)

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("slack sender: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack sender: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack sender: HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	// Drain body to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError {
		return &HTTPError{
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("slack sender: HTTP %d from webhook", resp.StatusCode),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack sender: HTTP %d from webhook", resp.StatusCode)
	}

	return nil
}
