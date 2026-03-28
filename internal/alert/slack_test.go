package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlackSender_BlockKitFormat(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewSlackSender(srv.URL)
	payload := AlertPayload{
		EventType:  "QUARANTINED",
		ArtifactID: "pypi:litellm:1.82.7",
		Reason:     "verdict SUSPICIOUS",
		Timestamp:  time.Date(2026, 3, 28, 14, 30, 0, 0, time.UTC),
	}

	err := sender.Send(context.Background(), payload)
	require.NoError(t, err)

	assert.Equal(t, "application/json", receivedContentType)

	// Parse the Block Kit structure.
	var msg slackMessage
	err = json.Unmarshal(receivedBody, &msg)
	require.NoError(t, err)
	require.Len(t, msg.Blocks, 3)

	// Header block.
	assert.Equal(t, "header", msg.Blocks[0].Type)
	require.NotNil(t, msg.Blocks[0].Text)
	assert.Equal(t, "plain_text", msg.Blocks[0].Text.Type)
	assert.Equal(t, "Artifact Quarantined", msg.Blocks[0].Text.Text)

	// Section block with fields.
	assert.Equal(t, "section", msg.Blocks[1].Type)
	require.Len(t, msg.Blocks[1].Fields, 2)
	assert.Equal(t, "mrkdwn", msg.Blocks[1].Fields[0].Type)
	assert.Equal(t, "*Artifact:*\npypi:litellm:1.82.7", msg.Blocks[1].Fields[0].Text)
	assert.Equal(t, "mrkdwn", msg.Blocks[1].Fields[1].Type)
	assert.Equal(t, "*Reason:*\nverdict SUSPICIOUS", msg.Blocks[1].Fields[1].Text)

	// Context block.
	assert.Equal(t, "context", msg.Blocks[2].Type)
	require.Len(t, msg.Blocks[2].Elements, 1)
	assert.Equal(t, "mrkdwn", msg.Blocks[2].Elements[0].Type)
	assert.Equal(t, "2026-03-28T14:30:00Z", msg.Blocks[2].Elements[0].Text)
}

func TestSlackSender_EventTitles(t *testing.T) {
	tests := []struct {
		eventType string
		expected  string
	}{
		{"BLOCKED", "Artifact Blocked"},
		{"QUARANTINED", "Artifact Quarantined"},
		{"RELEASED", "Artifact Released"},
		{"TAG_MUTATED", "Tag Digest Changed"},
		{"RESCAN_QUEUED", "Rescan Queued"},
		{"OVERRIDE_CREATED", "Override Created"},
		{"OVERRIDE_REVOKED", "Override Revoked"},
		{"UNKNOWN_EVENT", "Security Event: UNKNOWN_EVENT"},
		{"SERVED", "Security Event: SERVED"},
	}

	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			assert.Equal(t, tt.expected, eventTitle(tt.eventType))
		})
	}
}

func TestSlackSender_ReturnsHTTPErrorOnClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	sender := NewSlackSender(srv.URL)
	err := sender.Send(context.Background(), testPayload())

	require.Error(t, err)

	// Should be an HTTPError so the worker knows not to retry.
	var httpErr *HTTPError
	require.True(t, isHTTPError(err, &httpErr), "4xx should return HTTPError")
	assert.Equal(t, http.StatusForbidden, httpErr.StatusCode)

	// Also verify it works with the isClientError helper from alerter.go.
	assert.True(t, isClientError(err))
}

func TestSlackSender_ReturnsPlainErrorOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	sender := NewSlackSender(srv.URL)
	err := sender.Send(context.Background(), testPayload())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "502")

	// Should NOT be an HTTPError (5xx is retryable).
	var httpErr *HTTPError
	assert.False(t, isHTTPError(err, &httpErr),
		"5xx should not return HTTPError — it should be retried")
}

func TestSlackSender_Name(t *testing.T) {
	sender := NewSlackSender("https://hooks.slack.com/services/T00/B00/xxx")
	assert.Equal(t, "slack", sender.Name())
}
