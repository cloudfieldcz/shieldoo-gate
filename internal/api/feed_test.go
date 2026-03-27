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

func TestHandleListFeed_Empty_ReturnsEmptyArray(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.NotNil(t, body)
	assert.Empty(t, body)
}

func TestHandleListFeed_WithEntries_ReturnsList(t *testing.T) {
	srv, db := newTestServer(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO threat_feed (sha256, ecosystem, package_name, version, reported_at, source_url, iocs_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"deadbeef1234", "pypi", "malicious-pkg", "1.0.0", now, "https://example.com/feed", "[]",
	)
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/feed", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Len(t, body, 1)

	entry := body[0].(map[string]any)
	assert.Equal(t, "pypi", entry["ecosystem"])
	assert.Equal(t, "malicious-pkg", entry["package_name"])
}

func TestHandleRefreshFeed_Returns202(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feed/refresh", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "accepted", body["status"])
}
