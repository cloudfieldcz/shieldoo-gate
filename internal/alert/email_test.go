package alert

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailSender_Name(t *testing.T) {
	e := NewEmailSender("localhost", 587, "from@example.com", []string{"to@example.com"}, "", "", false, false, 1*time.Hour)
	defer e.Close()
	assert.Equal(t, "email", e.Name())
}

func TestEmailSender_BatchesMultipleEvents(t *testing.T) {
	var mu sync.Mutex
	var batches [][]AlertPayload

	e := NewEmailSender("localhost", 587, "from@example.com", []string{"to@example.com"}, "", "", false, false, 100*time.Millisecond)
	e.sendFunc = func(batch []AlertPayload) error {
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		return nil
	}

	// Send 3 events quickly.
	ctx := context.Background()
	require.NoError(t, e.Send(ctx, AlertPayload{EventType: "BLOCKED", ArtifactID: "pypi:malware:0.1", Reason: "malicious", Timestamp: time.Now()}))
	require.NoError(t, e.Send(ctx, AlertPayload{EventType: "QUARANTINED", ArtifactID: "pypi:litellm:1.82.7", Reason: "suspicious", Timestamp: time.Now()}))
	require.NoError(t, e.Send(ctx, AlertPayload{EventType: "BLOCKED", ArtifactID: "npm:evil-pkg:1.0.0", Reason: "malicious", Timestamp: time.Now()}))

	// Wait for the batch timer to fire.
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// All 3 events should arrive in a single batch.
	require.Len(t, batches, 1, "expected exactly 1 batch send")
	assert.Len(t, batches[0], 3, "expected 3 events in the batch")
}

func TestEmailSender_FlushOnClose(t *testing.T) {
	var mu sync.Mutex
	var batches [][]AlertPayload

	// Very long batchWait so the ticker won't fire during the test.
	e := NewEmailSender("localhost", 587, "from@example.com", []string{"to@example.com"}, "", "", false, false, 1*time.Hour)
	e.sendFunc = func(batch []AlertPayload) error {
		mu.Lock()
		batches = append(batches, batch)
		mu.Unlock()
		return nil
	}

	ctx := context.Background()
	require.NoError(t, e.Send(ctx, AlertPayload{EventType: "BLOCKED", ArtifactID: "pypi:foo:1.0", Reason: "bad", Timestamp: time.Now()}))

	// Close should flush.
	e.Close()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, batches, 1)
	assert.Len(t, batches[0], 1)
}

func TestEmailSender_NoBatchWhenEmpty(t *testing.T) {
	sendCount := 0
	e := NewEmailSender("localhost", 587, "from@example.com", []string{"to@example.com"}, "", "", false, false, 50*time.Millisecond)
	e.sendFunc = func(batch []AlertPayload) error {
		sendCount++
		return nil
	}

	// Let a few ticks pass with no events.
	time.Sleep(200 * time.Millisecond)
	e.Close()

	assert.Equal(t, 0, sendCount, "should not send when no events are pending")
}

func TestEmailSender_SubjectFormat(t *testing.T) {
	batch := []AlertPayload{
		{EventType: "QUARANTINED", ArtifactID: "pypi:litellm:1.82.7"},
		{EventType: "BLOCKED", ArtifactID: "pypi:malware-pkg:0.1.0"},
		{EventType: "BLOCKED", ArtifactID: "npm:evil:1.0"},
	}

	subject := FormatSubject(batch)
	assert.Equal(t, "[Shieldoo Gate] 3 security event(s): BLOCKED, QUARANTINED", subject)
}

func TestEmailSender_SubjectFormat_SingleEvent(t *testing.T) {
	batch := []AlertPayload{
		{EventType: "BLOCKED", ArtifactID: "pypi:malware:1.0"},
	}
	subject := FormatSubject(batch)
	assert.Equal(t, "[Shieldoo Gate] 1 security event(s): BLOCKED", subject)
}

func TestEmailSender_BodyFormat(t *testing.T) {
	ts1 := time.Date(2026, 3, 28, 14, 30, 0, 0, time.UTC)
	ts2 := time.Date(2026, 3, 28, 14, 30, 5, 0, time.UTC)

	batch := []AlertPayload{
		{EventType: "QUARANTINED", ArtifactID: "pypi:litellm:1.82.7", Reason: "verdict SUSPICIOUS meets quarantine threshold", Timestamp: ts1},
		{EventType: "BLOCKED", ArtifactID: "pypi:malware-pkg:0.1.0", Reason: "verdict MALICIOUS", Timestamp: ts2},
	}

	body := FormatBody(batch)

	assert.Contains(t, body, "Shieldoo Gate Security Alert")
	assert.Contains(t, body, "2 event(s) detected:")
	assert.Contains(t, body, "1. [QUARANTINED] pypi:litellm:1.82.7")
	assert.Contains(t, body, "   Reason: verdict SUSPICIOUS meets quarantine threshold")
	assert.Contains(t, body, "   Time: 2026-03-28T14:30:00Z")
	assert.Contains(t, body, "2. [BLOCKED] pypi:malware-pkg:0.1.0")
	assert.Contains(t, body, "   Reason: verdict MALICIOUS")
	assert.Contains(t, body, "   Time: 2026-03-28T14:30:05Z")
}

func TestBuildMIME(t *testing.T) {
	msg := buildMIME("from@example.com", []string{"a@example.com", "b@example.com"}, "Test Subject", "Hello body")
	s := string(msg)

	assert.True(t, strings.Contains(s, "From: from@example.com\r\n"))
	assert.True(t, strings.Contains(s, "To: a@example.com, b@example.com\r\n"))
	assert.True(t, strings.Contains(s, "Subject: Test Subject\r\n"))
	assert.True(t, strings.Contains(s, "Content-Type: text/plain; charset=UTF-8\r\n"))
	assert.True(t, strings.Contains(s, "\r\n\r\nHello body"))
}

func TestEmailSender_ImplementsChannelSender(t *testing.T) {
	// This is also checked at compile time, but an explicit test
	// makes the intent visible.
	var _ ChannelSender = (*EmailSender)(nil)
}
