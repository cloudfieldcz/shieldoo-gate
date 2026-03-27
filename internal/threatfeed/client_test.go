package threatfeed_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/threatfeed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleFeed(entries []threatfeed.FeedEntry) []byte {
	resp := threatfeed.FeedResponse{
		SchemaVersion: "1",
		Updated:       "2026-03-26T00:00:00Z",
		Entries:       entries,
	}
	data, _ := json.Marshal(resp)
	return data
}

func countRows(t *testing.T, db interface{ QueryRowContext(ctx context.Context, query string, args ...interface{}) interface{ Scan(...interface{}) error } }) int {
	t.Helper()
	return 0
}

func TestClient_Refresh_StoresEntries(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	entry := threatfeed.FeedEntry{
		SHA256:      "abc123",
		Ecosystem:   "pypi",
		PackageName: "evil-pkg",
		Versions:    []string{"1.0.0"},
		ReportedAt:  "2026-03-01T00:00:00Z",
		SourceURL:   "https://example.com",
		IoCs:        []string{"typosquat"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(sampleFeed([]threatfeed.FeedEntry{entry}))
	}))
	defer srv.Close()

	client := threatfeed.NewClient(db, srv.URL)
	err = client.Refresh(context.Background())
	require.NoError(t, err)

	var count int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM threat_feed").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestClient_Refresh_ServerDown_ReturnsError(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	client := threatfeed.NewClient(db, "http://127.0.0.1:1") // unreachable
	err = client.Refresh(context.Background())
	assert.Error(t, err)
}

func TestClient_Refresh_Idempotent(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	entry := threatfeed.FeedEntry{
		SHA256:      "def456",
		Ecosystem:   "npm",
		PackageName: "malicious-lib",
		Versions:    []string{"2.0.0"},
		ReportedAt:  "2026-03-02T00:00:00Z",
		SourceURL:   "https://example.com/npm",
		IoCs:        []string{"obfuscation"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(sampleFeed([]threatfeed.FeedEntry{entry}))
	}))
	defer srv.Close()

	client := threatfeed.NewClient(db, srv.URL)

	// Refresh twice.
	require.NoError(t, client.Refresh(context.Background()))
	require.NoError(t, client.Refresh(context.Background()))

	var count int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM threat_feed").Scan(&count)
	require.NoError(t, err)
	// INSERT OR REPLACE means there should still be exactly 1 row.
	assert.Equal(t, 1, count)
}
