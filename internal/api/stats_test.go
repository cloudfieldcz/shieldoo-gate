package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleStatsSummary_Empty_ReturnsZeroCounts(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/summary", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	assert.Contains(t, body, "total_artifacts")
	assert.Contains(t, body, "total_blocked")
	assert.Contains(t, body, "total_quarantined")
	assert.Contains(t, body, "total_served")
	assert.Contains(t, body, "by_period")

	assert.Equal(t, float64(0), body["total_artifacts"])
	assert.Equal(t, float64(0), body["total_served"])
	assert.Equal(t, float64(0), body["total_blocked"])
}

func TestHandleStatsSummary_WithEvents_ReturnsCorrectCounts(t *testing.T) {
	srv, db := newTestServer(t)

	now := time.Now().UTC()
	insertAuditEvent := func(eventType string) {
		_, err := db.Exec(
			`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`,
			now, eventType,
		)
		require.NoError(t, err)
	}

	insertAuditEvent("SERVED")
	insertAuditEvent("SERVED")
	insertAuditEvent("BLOCKED")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/summary", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	assert.Equal(t, float64(2), body["total_served"])
	assert.Equal(t, float64(1), body["total_blocked"])

	// by_period should have 7 daily buckets.
	byPeriod := body["by_period"].(map[string]any)
	assert.Len(t, byPeriod, 7)

	// Today's bucket should contain the events.
	todayKey := now.Format("2006-01-02")
	todayBucket := byPeriod[todayKey].(map[string]any)
	assert.Equal(t, float64(2), todayBucket["served"])
	assert.Equal(t, float64(1), todayBucket["blocked"])
}

func TestHandleStatsBlocked_ReturnsJSONArray(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/blocked", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.NotNil(t, body)
}
