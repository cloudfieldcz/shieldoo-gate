package alert

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// mockSender is a test double for ChannelSender.
type mockSender struct {
	name     string
	mu       sync.Mutex
	payloads []AlertPayload
	sendErr  error
	sendFn   func(ctx context.Context, payload AlertPayload) error
}

func (m *mockSender) Name() string { return m.name }

func (m *mockSender) Send(ctx context.Context, payload AlertPayload) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, payload)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.payloads = append(m.payloads, payload)
	return nil
}

func (m *mockSender) received() []AlertPayload {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]AlertPayload, len(m.payloads))
	copy(cp, m.payloads)
	return cp
}

func makeEntry(eventType model.EventType) model.AuditEntry {
	return model.AuditEntry{
		ID:           1,
		Timestamp:    time.Date(2026, 3, 28, 12, 0, 0, 0, time.UTC),
		EventType:    eventType,
		ArtifactID:   "pypi/requests/2.31.0",
		ClientIP:     "10.0.0.1",
		UserAgent:    "pip/24.0",
		Reason:       "malicious package detected",
		MetadataJSON: `{"scanner":"guarddog","verdict":"MALICIOUS"}`,
	}
}

func TestMultiAlerter_DispatchesToAllChannels(t *testing.T) {
	s1 := &mockSender{name: "ch1"}
	s2 := &mockSender{name: "ch2"}

	alerter := NewMultiAlerter([]ChannelConfig{
		{Channel: s1},
		{Channel: s2},
	})

	entry := makeEntry(model.EventBlocked)
	alerter.Dispatch(context.Background(), entry)

	err := alerter.Close()
	require.NoError(t, err)

	assert.Len(t, s1.received(), 1)
	assert.Len(t, s2.received(), 1)
	assert.Equal(t, "BLOCKED", s1.received()[0].EventType)
	assert.Equal(t, "BLOCKED", s2.received()[0].EventType)
}

func TestMultiAlerter_FiltersEventTypes(t *testing.T) {
	s1 := &mockSender{name: "blocked-only"}
	s2 := &mockSender{name: "all-events"}

	alerter := NewMultiAlerter([]ChannelConfig{
		{Channel: s1, EventFilter: []model.EventType{model.EventBlocked}},
		{Channel: s2}, // no filter = all events
	})

	alerter.Dispatch(context.Background(), makeEntry(model.EventBlocked))
	alerter.Dispatch(context.Background(), makeEntry(model.EventServed))
	alerter.Dispatch(context.Background(), makeEntry(model.EventQuarantined))

	err := alerter.Close()
	require.NoError(t, err)

	// s1 should only get BLOCKED
	assert.Len(t, s1.received(), 1)
	assert.Equal(t, "BLOCKED", s1.received()[0].EventType)

	// s2 should get all three
	assert.Len(t, s2.received(), 3)
}

func TestMultiAlerter_EmptyOnMatchesAll(t *testing.T) {
	s := &mockSender{name: "all"}

	alerter := NewMultiAlerter([]ChannelConfig{
		{Channel: s, EventFilter: nil},
	})

	alerter.Dispatch(context.Background(), makeEntry(model.EventBlocked))
	alerter.Dispatch(context.Background(), makeEntry(model.EventServed))
	alerter.Dispatch(context.Background(), makeEntry(model.EventScanned))

	err := alerter.Close()
	require.NoError(t, err)

	assert.Len(t, s.received(), 3)
}

func TestMultiAlerter_DropsWhenBufferFull(t *testing.T) {
	// Use a sender that blocks until we release it.
	unblock := make(chan struct{})
	var sent atomic.Int32

	s := &mockSender{
		name: "slow",
		sendFn: func(ctx context.Context, payload AlertPayload) error {
			<-unblock
			sent.Add(1)
			return nil
		},
	}

	bufSize := 4
	alerter := NewMultiAlerter([]ChannelConfig{
		{Channel: s, BufferSize: bufSize},
	})

	// The worker goroutine will pick up the first item and block on unblock.
	// That leaves bufSize slots in the channel. Fill them, then one more should drop.
	for i := range bufSize + 2 {
		alerter.Dispatch(context.Background(), makeEntry(model.EventBlocked))
		_ = i
	}

	// Give the worker time to pick up the first message and block.
	time.Sleep(50 * time.Millisecond)

	// Unblock and close.
	close(unblock)
	err := alerter.Close()
	require.NoError(t, err)

	// We should have sent at most bufSize+1 (the one being processed + bufSize in queue).
	// At least 1 should have been dropped.
	assert.LessOrEqual(t, int(sent.Load()), bufSize+1)
}

func TestMultiAlerter_CloseFlushes(t *testing.T) {
	var sent atomic.Int32

	s := &mockSender{
		name: "counter",
		sendFn: func(ctx context.Context, payload AlertPayload) error {
			sent.Add(1)
			return nil
		},
	}

	alerter := NewMultiAlerter([]ChannelConfig{
		{Channel: s, BufferSize: 64},
	})

	n := 20
	for range n {
		alerter.Dispatch(context.Background(), makeEntry(model.EventBlocked))
	}

	err := alerter.Close()
	require.NoError(t, err)

	// After Close, all dispatched alerts should have been processed.
	assert.Equal(t, int32(n), sent.Load())
}

func TestAlertPayload_NoClientIPOrUserAgent(t *testing.T) {
	entry := makeEntry(model.EventBlocked)
	assert.NotEmpty(t, entry.ClientIP, "test precondition: entry should have ClientIP")
	assert.NotEmpty(t, entry.UserAgent, "test precondition: entry should have UserAgent")

	payload := NewAlertPayload(entry)

	// Verify no ClientIP or UserAgent in the payload struct.
	assert.Equal(t, "BLOCKED", payload.EventType)
	assert.Equal(t, "pypi/requests/2.31.0", payload.ArtifactID)
	assert.Equal(t, "malicious package detected", payload.Reason)

	// Also verify it does not appear in the JSON serialization.
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "10.0.0.1")
	assert.NotContains(t, jsonStr, "pip/24.0")
	assert.NotContains(t, jsonStr, "client_ip")
	assert.NotContains(t, jsonStr, "user_agent")

	// Metadata should be parsed.
	meta, ok := payload.Metadata.(map[string]any)
	require.True(t, ok, "metadata should be a map")
	assert.Equal(t, "guarddog", meta["scanner"])
	assert.Equal(t, "MALICIOUS", meta["verdict"])
}

func TestAlertPayload_EmptyMetadata(t *testing.T) {
	entry := model.AuditEntry{
		EventType:  model.EventServed,
		ArtifactID: "npm/lodash/4.17.21",
		Timestamp:  time.Now(),
	}

	payload := NewAlertPayload(entry)
	assert.Nil(t, payload.Metadata)
}

func TestChannelWorker_RetryOnServerError(t *testing.T) {
	var attempts atomic.Int32

	s := &mockSender{
		name: "flaky",
		sendFn: func(ctx context.Context, payload AlertPayload) error {
			n := attempts.Add(1)
			if n < 3 {
				return errors.New("server error")
			}
			return nil
		},
	}

	alerter := NewMultiAlerter([]ChannelConfig{
		{Channel: s, BufferSize: 8, RetryBaseDelay: 10 * time.Millisecond},
	})

	alerter.Dispatch(context.Background(), makeEntry(model.EventBlocked))

	err := alerter.Close()
	require.NoError(t, err)

	assert.Equal(t, int32(3), attempts.Load())
}

func TestChannelWorker_NoRetryOnClientError(t *testing.T) {
	var attempts atomic.Int32

	s := &mockSender{
		name: "client-err",
		sendFn: func(ctx context.Context, payload AlertPayload) error {
			attempts.Add(1)
			return &HTTPError{StatusCode: 400, Err: errors.New("bad request")}
		},
	}

	alerter := NewMultiAlerter([]ChannelConfig{
		{Channel: s, BufferSize: 8, RetryBaseDelay: 10 * time.Millisecond},
	})

	alerter.Dispatch(context.Background(), makeEntry(model.EventBlocked))

	err := alerter.Close()
	require.NoError(t, err)

	// Should only have tried once due to 4xx.
	assert.Equal(t, int32(1), attempts.Load())
}
