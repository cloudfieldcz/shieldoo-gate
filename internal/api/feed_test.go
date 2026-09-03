package api_test

import (
	"context"
	"encoding/json"
	"errors"
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

func TestHandleRefreshFeed_NoRefresherWired_Returns501(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feed/refresh", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// It used to answer 202 "queued" here and do nothing, which sends an
	// operator chasing a dead feed looking for a second, non-existent fault.
	assert.Equal(t, http.StatusNotImplemented, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Contains(t, body["error"], "not available")
}

func TestHandleRefreshFeed_RefresherWired_Returns202AndRunsRefresh(t *testing.T) {
	srv, _ := newTestServer(t)

	called := make(chan context.Context, 1)
	srv.SetFeedRefresher(func(ctx context.Context) error {
		called <- ctx
		return nil
	})
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feed/refresh", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "accepted", body["status"])

	select {
	case ctx := <-called:
		// The refresh must outlive the request it was triggered by.
		assert.NoError(t, ctx.Err(), "refresh context must not be the (finished) request context")
		deadline, ok := ctx.Deadline()
		assert.True(t, ok, "the detached refresh must still be bounded")
		assert.True(t, deadline.After(time.Now()))
	case <-time.After(2 * time.Second):
		t.Fatal("202 was returned but the refresh never ran")
	}
}

func TestHandleRefreshFeed_RefreshFails_StillReturns202(t *testing.T) {
	srv, _ := newTestServer(t)

	done := make(chan struct{})
	srv.SetFeedRefresher(func(context.Context) error {
		defer close(done)
		return errors.New("feed host unreachable")
	})
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feed/refresh", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// The response is already written by the time the fetch fails; the failure
	// surfaces through the same log line and metrics as a scheduled refresh.
	assert.Equal(t, http.StatusAccepted, rec.Code)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the refresh never ran")
	}
}
