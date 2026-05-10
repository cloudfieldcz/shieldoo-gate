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

// eventTitle delegates to the package-level EventTitle so vuln-scan events get
// their curated header text. Kept as a thin wrapper for backward compatibility
// with existing tests that import the lowercase symbol.
func eventTitle(eventType string) string {
	return EventTitle(eventType)
}

// buildSlackMessage constructs a Slack Block Kit message from an AlertPayload.
// Vuln-scan events get a "Component" / "Scan run" / "Ignore" field row when
// the structured FK columns are populated; legacy proxy events render the
// pre-existing Artifact + Reason layout unchanged.
func buildSlackMessage(payload AlertPayload) slackMessage {
	mainFields := []slackTextObj{}
	if payload.ArtifactID != "" {
		mainFields = append(mainFields, slackTextObj{Type: "mrkdwn", Text: "*Artifact:*\n" + payload.ArtifactID})
	}
	if payload.ComponentID != nil && *payload.ComponentID > 0 {
		mainFields = append(mainFields, slackTextObj{Type: "mrkdwn", Text: fmt.Sprintf("*Component:*\n#%d", *payload.ComponentID)})
	}
	if payload.ScanRunID != nil && *payload.ScanRunID > 0 {
		mainFields = append(mainFields, slackTextObj{Type: "mrkdwn", Text: fmt.Sprintf("*Scan run:*\n#%d", *payload.ScanRunID)})
	}
	if payload.IgnoreID != nil && *payload.IgnoreID > 0 {
		mainFields = append(mainFields, slackTextObj{Type: "mrkdwn", Text: fmt.Sprintf("*Ignore:*\n#%d", *payload.IgnoreID)})
	}
	mainFields = append(mainFields, slackTextObj{Type: "mrkdwn", Text: "*Reason:*\n" + payload.Reason})

	return slackMessage{
		Blocks: []slackBlock{
			{
				Type: "header",
				Text: &slackTextObj{
					Type: "plain_text",
					Text: EventTitle(payload.EventType),
				},
			},
			{
				Type:   "section",
				Fields: mainFields,
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
