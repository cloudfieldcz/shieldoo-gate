package threatfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshFailureLevel_Thresholds_EscalatesToError(t *testing.T) {
	tests := []struct {
		name        string
		consecutive int
		entries     int64
		want        zerolog.Level
	}{
		{"first failure with a populated feed is a warning", 1, 12, zerolog.WarnLevel},
		{"still a warning just below the threshold", escalateAfterConsecutiveFailures - 1, 12, zerolog.WarnLevel},
		{"escalates at the threshold", escalateAfterConsecutiveFailures, 12, zerolog.ErrorLevel},
		{"stays escalated above the threshold", 535, 12, zerolog.ErrorLevel},
		{"an empty feed is an error from the first failure", 1, 0, zerolog.ErrorLevel},
		{"an uncountable feed is treated as populated", 1, entriesUnknown, zerolog.WarnLevel},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, refreshFailureLevel(tc.consecutive, tc.entries))
		})
	}
}

// captureLogs redirects the global zerolog logger into a buffer for the
// duration of the test and returns the decoded JSON lines.
func captureLogs(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	original := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = original })

	fn()

	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if raw == "" {
			continue
		}
		var line map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &line), "log line must be valid JSON: %s", raw)
		lines = append(lines, line)
	}
	return lines
}

func TestClient_RefreshAndLog_EmptyFeedFailure_LogsErrorNamingTheFailOpen(t *testing.T) {
	resetFeedMetrics(t)
	client := NewClient(testDB(t), "https://feed.example.invalid/feed.json")

	lines := captureLogs(t, func() { _ = client.RefreshNow(context.Background()) })

	require.Len(t, lines, 1)
	assert.Equal(t, "error", lines[0]["level"], "a first failure with an empty feed must not be a warning")
	assert.Contains(t, lines[0]["message"], "empty")
	assert.Contains(t, lines[0]["message"], "builtin-threat-feed")
	assert.Equal(t, false, lines[0]["ever_loaded"], "the never-loaded case must be explicit in the line")
	assert.Equal(t, 0.0, lines[0]["feed_entries"])
	assert.Equal(t, 1.0, lines[0]["consecutive_failures"])
}

func TestClient_RefreshAndLog_PopulatedFeedFailures_WarnsThenEscalates(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("ddd444")})
	client := NewClient(testDB(t), srv.URL)
	require.NoError(t, client.refreshOnce(context.Background()).err)
	srv.Close()

	wantLevels := []string{"warn", "warn", "error", "error"}
	for i, want := range wantLevels {
		lines := captureLogs(t, func() { _ = client.RefreshNow(context.Background()) })
		require.Len(t, lines, 1)
		assert.Equal(t, want, lines[0]["level"], "failure %d", i+1)
		assert.Equal(t, float64(i+1), lines[0]["consecutive_failures"])
		assert.Equal(t, 1.0, lines[0]["feed_entries"])
		// A feed that did load once reports how stale it is, in readable units,
		// instead of the never-loaded marker.
		assert.NotContains(t, lines[0], "ever_loaded")
		assert.Regexp(t, `^\d+(\.\d+)?(h|m|s)`, lines[0]["stale_for"])
		assert.Contains(t, lines[0]["message"], "last feed contents")
	}
}

func TestClient_RefreshAndLog_Success_LogsInfoWithEntryCount(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("eee555"), maliciousEntry("fff666")})
	client := NewClient(testDB(t), srv.URL)

	lines := captureLogs(t, func() { _ = client.RefreshNow(context.Background()) })

	require.Len(t, lines, 1)
	assert.Equal(t, "info", lines[0]["level"])
	assert.Equal(t, 2.0, lines[0]["feed_entries"])
}

func TestClient_RefreshAndLog_SuccessWithEmptyFeed_LogsError(t *testing.T) {
	resetFeedMetrics(t)
	// A perfectly healthy exchange: 200, valid JSON, zero entries.
	srv := feedServer(t, nil)
	client := NewClient(testDB(t), srv.URL)

	lines := captureLogs(t, func() { _ = client.RefreshNow(context.Background()) })

	require.Len(t, lines, 1)
	assert.Equal(t, "error", lines[0]["level"], "a successful refresh that leaves the feed empty is the same fail-open as a failed one")
	assert.Equal(t, 0.0, lines[0]["feed_entries"])
	assert.NotContains(t, lines[0], "error", "there is no fetch error to report on the success path")
	assert.Contains(t, lines[0]["message"], "empty")
	assert.Contains(t, lines[0]["message"], "builtin-threat-feed")
}

func TestClient_Run_CancelledContext_RefreshesOnceAndReturns(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("999999")})
	client := NewClient(testDB(t), srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		client.Run(ctx, time.Hour)
		close(done)
	}()

	// The immediate refresh happens before the first tick.
	require.Eventually(t, func() bool {
		successes, _ := metricValue(t, "shieldoo_gate_threat_feed_refresh_total", map[string]string{"result": resultSuccess})
		return successes == 1
	}, 2*time.Second, 10*time.Millisecond, "Run must refresh once immediately, not wait for the first tick")

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestClient_RefreshNow_Failure_ReturnsTheErrorItLogged(t *testing.T) {
	resetFeedMetrics(t)
	client := NewClient(testDB(t), "https://feed.example.invalid/feed.json")

	var err error
	lines := captureLogs(t, func() { err = client.RefreshNow(context.Background()) })

	// The manual-refresh caller gets the error back, but the reporting has
	// already happened — it must not log it a second time.
	require.Error(t, err, "RefreshNow must hand the refresh error back to out-of-band callers")
	require.Len(t, lines, 1, "exactly one line per refresh attempt, whoever triggered it")
	assert.Equal(t, "error", lines[0]["level"])
}

func TestClient_RefreshNow_Success_ReturnsNil(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("abcabc")})
	client := NewClient(testDB(t), srv.URL)

	var err error
	captureLogs(t, func() { err = client.RefreshNow(context.Background()) })

	assert.NoError(t, err)
}

func TestClient_Run_Ticks_RefreshesRepeatedly(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("777777")})
	client := NewClient(testDB(t), srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx, 20*time.Millisecond)

	require.Eventually(t, func() bool {
		successes, _ := metricValue(t, "shieldoo_gate_threat_feed_refresh_total", map[string]string{"result": resultSuccess})
		return successes >= 3
	}, 3*time.Second, 10*time.Millisecond, "Run must keep refreshing on every tick")
}
