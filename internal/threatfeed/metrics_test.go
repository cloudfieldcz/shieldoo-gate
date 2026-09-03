package threatfeed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetFeedMetrics clears the package-level metrics so a test starts from the
// same state the process starts in. The metrics live on the default registry,
// so tests in this package must not run in parallel.
func resetFeedMetrics(t *testing.T) {
	t.Helper()
	refreshTotal.Reset()
	refreshConsecutiveFailures.Set(0)
	lastSuccessTimestamp.Set(0)
	feedEntries.Set(0)
	feedEnabled.Set(0)
}

// metricValue reads a single series from the default registry. found is false
// when the metric family or the label combination is absent.
func metricValue(t *testing.T, name string, labels map[string]string) (value float64, found bool) {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := true
			for _, pair := range metric.GetLabel() {
				if want, ok := labels[pair.GetName()]; ok && want != pair.GetValue() {
					matched = false
					break
				}
			}
			if len(metric.GetLabel()) != len(labels) {
				matched = false
			}
			if !matched {
				continue
			}
			if metric.Gauge != nil {
				return metric.GetGauge().GetValue(), true
			}
			return metric.GetCounter().GetValue(), true
		}
	}
	return 0, false
}

// feedServer serves a feed with the given entries.
func feedServer(t *testing.T, entries []FeedEntry) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(FeedResponse{
			SchemaVersion: "1",
			Updated:       "2026-09-03T00:00:00Z",
			Entries:       entries,
		}))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func maliciousEntry(sha string) FeedEntry {
	return FeedEntry{
		SHA256:      sha,
		Ecosystem:   "pypi",
		PackageName: "evil-pkg",
		Versions:    []string{"1.0.0"},
		ReportedAt:  "2026-09-01T00:00:00Z",
		SourceURL:   "https://example.com",
		IoCs:        []string{"typosquat"},
	}
}

func TestNewClient_Constructed_MarksFeedEnabledAndZeroSuccess(t *testing.T) {
	resetFeedMetrics(t)

	NewClient(testDB(t), "https://feed.example.invalid/feed.json")

	enabled, found := metricValue(t, "shieldoo_gate_threat_feed_enabled", nil)
	require.True(t, found)
	assert.Equal(t, 1.0, enabled, "an existing client must report the feed as enabled")

	// The never-loaded signal: the timestamp gauge is present and zero rather
	// than absent, so an alert can tell it apart from an unreachable scrape.
	ts, found := metricValue(t, "shieldoo_gate_threat_feed_last_success_timestamp_seconds", nil)
	require.True(t, found, "last-success gauge must exist before the first refresh")
	assert.Equal(t, 0.0, ts)

	// Both counter series exist at zero for the same reason.
	successes, found := metricValue(t, "shieldoo_gate_threat_feed_refresh_total", map[string]string{"result": resultSuccess})
	require.True(t, found, "success counter must exist before the first refresh")
	assert.Equal(t, 0.0, successes)
	failures, found := metricValue(t, "shieldoo_gate_threat_feed_refresh_total", map[string]string{"result": resultFailure})
	require.True(t, found)
	assert.Equal(t, 0.0, failures)
}

func TestClient_Refresh_Success_RecordsTimestampAndEntries(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("aaa111")})
	client := NewClient(testDB(t), srv.URL)

	before := time.Now().Add(-time.Second)
	require.NoError(t, client.Refresh(context.Background()))

	successes, _ := metricValue(t, "shieldoo_gate_threat_feed_refresh_total", map[string]string{"result": resultSuccess})
	assert.Equal(t, 1.0, successes)

	consecutive, _ := metricValue(t, "shieldoo_gate_threat_feed_consecutive_failures", nil)
	assert.Equal(t, 0.0, consecutive)

	ts, _ := metricValue(t, "shieldoo_gate_threat_feed_last_success_timestamp_seconds", nil)
	assert.GreaterOrEqual(t, ts, float64(before.Unix()), "last-success timestamp must move to now")

	entries, _ := metricValue(t, "shieldoo_gate_threat_feed_entries", nil)
	assert.Equal(t, 1.0, entries)
}

func TestClient_Refresh_NeverLoaded_KeepsTimestampZeroAndEntriesZero(t *testing.T) {
	resetFeedMetrics(t)
	client := NewClient(testDB(t), "https://feed.example.invalid/feed.json")

	require.Error(t, client.Refresh(context.Background()))

	// This is the production shape: repeated failures, nothing ever loaded.
	ts, found := metricValue(t, "shieldoo_gate_threat_feed_last_success_timestamp_seconds", nil)
	require.True(t, found)
	assert.Equal(t, 0.0, ts, "a feed that never loaded must keep a zero last-success timestamp")

	entries, found := metricValue(t, "shieldoo_gate_threat_feed_entries", nil)
	require.True(t, found)
	assert.Equal(t, 0.0, entries, "an empty local feed must be visible as zero entries")

	failures, _ := metricValue(t, "shieldoo_gate_threat_feed_refresh_total", map[string]string{"result": resultFailure})
	assert.Equal(t, 1.0, failures)

	consecutive, _ := metricValue(t, "shieldoo_gate_threat_feed_consecutive_failures", nil)
	assert.Equal(t, 1.0, consecutive)
}

func TestClient_Refresh_FailureAfterSuccess_KeepsLastSuccessAndCountsUp(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("bbb222")})
	db := testDB(t)
	client := NewClient(db, srv.URL)
	require.NoError(t, client.Refresh(context.Background()))

	loadedAt, _ := metricValue(t, "shieldoo_gate_threat_feed_last_success_timestamp_seconds", nil)
	require.NotZero(t, loadedAt)

	// The feed host goes away; the local table keeps its contents.
	srv.Close()
	for i := 1; i <= 3; i++ {
		require.Error(t, client.Refresh(context.Background()))

		consecutive, _ := metricValue(t, "shieldoo_gate_threat_feed_consecutive_failures", nil)
		assert.Equal(t, float64(i), consecutive)
	}

	ts, _ := metricValue(t, "shieldoo_gate_threat_feed_last_success_timestamp_seconds", nil)
	assert.Equal(t, loadedAt, ts, "failures must not clear the last-success timestamp — that is what makes stale distinguishable from never-loaded")

	entries, _ := metricValue(t, "shieldoo_gate_threat_feed_entries", nil)
	assert.Equal(t, 1.0, entries, "a failed refresh must still report the rows the scanner matches against")

	failures, _ := metricValue(t, "shieldoo_gate_threat_feed_refresh_total", map[string]string{"result": resultFailure})
	assert.Equal(t, 3.0, failures)
}

func TestClient_Refresh_SuccessAfterFailures_ResetsConsecutiveGauge(t *testing.T) {
	resetFeedMetrics(t)
	srv := feedServer(t, []FeedEntry{maliciousEntry("ccc333")})
	client := NewClient(testDB(t), srv.URL)

	client.mu.Lock()
	client.consecutiveFailures = 7
	client.mu.Unlock()
	recordRefreshFailure(7, 0)

	consecutive, _ := metricValue(t, "shieldoo_gate_threat_feed_consecutive_failures", nil)
	require.Equal(t, 7.0, consecutive)

	require.NoError(t, client.Refresh(context.Background()))

	consecutive, _ = metricValue(t, "shieldoo_gate_threat_feed_consecutive_failures", nil)
	assert.Equal(t, 0.0, consecutive, "a successful refresh must clear the consecutive-failure gauge")
}

func TestSetFeedEntries_UnknownCount_LeavesPreviousValue(t *testing.T) {
	resetFeedMetrics(t)
	setFeedEntries(42)
	setFeedEntries(entriesUnknown)

	entries, _ := metricValue(t, "shieldoo_gate_threat_feed_entries", nil)
	assert.Equal(t, 42.0, entries, "an uncountable table must not be reported as an empty one")
}

func TestClient_CountEntries_CancelledContext_ReturnsUnknown(t *testing.T) {
	client := NewClient(testDB(t), "https://feed.example.invalid/feed.json")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.Equal(t, entriesUnknown, client.countEntries(ctx))
}
