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

func TestHandleListAudit_Empty_ReturnsEmptyArray(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	assert.Equal(t, float64(0), body["total"])
	assert.Equal(t, float64(1), body["page"])

	data, ok := body["data"].([]any)
	require.True(t, ok, "data should be an array")
	assert.Empty(t, data)
}

func TestHandleListAudit_WithEvents_ReturnsPaginated(t *testing.T) {
	srv, db := newTestServer(t)

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		_, err := db.Exec(
			`INSERT INTO audit_log (ts, event_type, artifact_id, reason)
			 VALUES (?, ?, ?, ?)`,
			now, "SERVED", "pypi:requests:2.31.0", "clean artifact",
		)
		require.NoError(t, err)
	}

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?page=1&per_page=2", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	assert.Equal(t, float64(3), body["total"])
	assert.Equal(t, float64(2), body["per_page"])

	data := body["data"].([]any)
	assert.Len(t, data, 2)
}

func TestHandleListAudit_FilterByEventType_ReturnsFiltered(t *testing.T) {
	srv, db := newTestServer(t)

	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`, now, "SERVED")
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`, now, "SERVED")
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`, now, "BLOCKED")
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit?event_type=BLOCKED", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	assert.Equal(t, float64(1), body["total"])

	data := body["data"].([]any)
	assert.Len(t, data, 1)

	entry := data[0].(map[string]any)
	assert.Equal(t, "BLOCKED", entry["event_type"])
}
