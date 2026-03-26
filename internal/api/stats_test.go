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

	// All three periods must be present.
	assert.Contains(t, body, "last_24h")
	assert.Contains(t, body, "last_7d")
	assert.Contains(t, body, "last_30d")

	// With no audit log rows all counts must be zero.
	period := body["last_24h"].(map[string]any)
	assert.Equal(t, float64(0), period["served"])
	assert.Equal(t, float64(0), period["blocked"])
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

	period := body["last_24h"].(map[string]any)
	assert.Equal(t, float64(2), period["served"])
	assert.Equal(t, float64(1), period["blocked"])
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
