package adapter_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestCheckDigestChanged_PyPI_ETagChanged(t *testing.T) {
	adapter.ClearHeadCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"new-etag-abc"`)
		w.Header().Set("Content-Length", "12345")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	changed, digest, err := adapter.CheckDigestChanged(context.Background(), "pypi", srv.URL+"/package.whl", "old-sha256-hash", &http.Client{})
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Contains(t, digest, "etag:")
}

func TestCheckDigestChanged_PyPI_ETagSame(t *testing.T) {
	adapter.ClearHeadCache()
	// When the cached "sha256" matches the upstream signature format, no change is detected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"stable-etag"`)
		w.Header().Set("Content-Length", "999")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Simulate that the cached digest was previously recorded in signature format.
	cachedDigest := `etag:"stable-etag";cl:999`
	changed, _, err := adapter.CheckDigestChanged(context.Background(), "pypi", srv.URL+"/package.whl", cachedDigest, &http.Client{})
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestCheckDigestChanged_npm_IntegrityChanged(t *testing.T) {
	adapter.ClearHeadCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"dist":{"integrity":"sha512-newAAAA","shasum":"abc123"}}`)
	}))
	defer srv.Close()

	// npm tarball URL format: baseURL/pkg/-/pkg-1.0.0.tgz
	tarballURL := srv.URL + "/is-odd/-/is-odd-3.0.1.tgz"
	changed, digest, err := adapter.CheckDigestChanged(context.Background(), "npm", tarballURL, "sha512-oldBBBB", &http.Client{})
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, "sha512-newAAAA", digest)
}

func TestCheckDigestChanged_npm_IntegritySame(t *testing.T) {
	adapter.ClearHeadCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"dist":{"integrity":"sha512-sameAAAA","shasum":"abc123"}}`)
	}))
	defer srv.Close()

	tarballURL := srv.URL + "/is-odd/-/is-odd-3.0.1.tgz"
	changed, _, err := adapter.CheckDigestChanged(context.Background(), "npm", tarballURL, "sha512-sameAAAA", &http.Client{})
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestCheckDigestChanged_FailOpen_OnError(t *testing.T) {
	adapter.ClearHeadCache()
	// Server that returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	changed, _, err := adapter.CheckDigestChanged(context.Background(), "pypi", srv.URL+"/package.whl", "some-sha256", &http.Client{})
	assert.Error(t, err)
	assert.False(t, changed, "should fail-open: treat as unchanged on error")
}

func TestCheckDigestChanged_FailOpen_NetworkError(t *testing.T) {
	adapter.ClearHeadCache()
	// Use an unreachable URL.
	changed, _, err := adapter.CheckDigestChanged(context.Background(), "pypi", "http://127.0.0.1:1/unreachable", "some-sha256", &http.Client{Timeout: 100 * time.Millisecond})
	assert.Error(t, err)
	assert.False(t, changed, "should fail-open on network error")
}

func TestCheckDigestChanged_HeadCaching(t *testing.T) {
	adapter.ClearHeadCache()
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("ETag", `"etag-cache-test"`)
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{}
	url := srv.URL + "/package.whl"

	// First call hits the server.
	_, _, err := adapter.CheckDigestChanged(context.Background(), "pypi", url, "old", client)
	require.NoError(t, err)
	assert.Equal(t, int32(1), requestCount.Load())

	// Second call should use the cache.
	_, _, err = adapter.CheckDigestChanged(context.Background(), "pypi", url, "old", client)
	require.NoError(t, err)
	assert.Equal(t, int32(1), requestCount.Load(), "second call should use cache, not make another request")

	// Third call with different URL should hit the server.
	_, _, err = adapter.CheckDigestChanged(context.Background(), "pypi", url+"/other", "old", client)
	require.NoError(t, err)
	assert.Equal(t, int32(2), requestCount.Load(), "different URL should make a new request")
}

func TestRecordDigestHistory_Idempotent(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Insert once.
	err = adapter.RecordDigestHistory(db, "pypi", "requests", "2.28.0", "sha256:abc123")
	require.NoError(t, err)

	// Insert again (same params) — should succeed (ON CONFLICT DO NOTHING).
	err = adapter.RecordDigestHistory(db, "pypi", "requests", "2.28.0", "sha256:abc123")
	require.NoError(t, err)

	// Insert different digest — should also succeed.
	err = adapter.RecordDigestHistory(db, "pypi", "requests", "2.28.0", "sha256:def456")
	require.NoError(t, err)

	// Verify both rows exist.
	var count int
	err = db.Get(&count, "SELECT COUNT(*) FROM tag_digest_history WHERE ecosystem = 'pypi' AND name = 'requests' AND tag_or_version = '2.28.0'")
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestTagMutability_ExcludeTags(t *testing.T) {
	excludeTags := []string{"latest", "nightly", "dev"}

	assert.True(t, adapter.IsExcludedTag("latest", excludeTags))
	assert.True(t, adapter.IsExcludedTag("LATEST", excludeTags), "should be case-insensitive")
	assert.True(t, adapter.IsExcludedTag("nightly", excludeTags))
	assert.True(t, adapter.IsExcludedTag("dev", excludeTags))
	assert.False(t, adapter.IsExcludedTag("1.0.0", excludeTags))
	assert.False(t, adapter.IsExcludedTag("v2.3.1", excludeTags))
	assert.False(t, adapter.IsExcludedTag("", excludeTags))
}

func TestHandleTagMutability_Disabled_NoCheck(t *testing.T) {
	cfg := config.TagMutabilityConfig{
		Enabled:         false,
		CheckOnCacheHit: true,
	}
	// Should return false immediately without making any HTTP requests.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	blocked := adapter.HandleTagMutability(context.Background(), cfg, nil, nil,
		"pypi", "pkg", "1.0.0", "pypi:pkg:1.0.0", "http://example.com/pkg", r, w)
	assert.False(t, blocked)
}

func TestHandleTagMutability_ExcludedTag_NoCheck(t *testing.T) {
	cfg := config.TagMutabilityConfig{
		Enabled:         true,
		CheckOnCacheHit: true,
		ExcludeTags:     []string{"latest"},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	blocked := adapter.HandleTagMutability(context.Background(), cfg, nil, nil,
		"pypi", "pkg", "latest", "pypi:pkg:latest", "http://example.com/pkg", r, w)
	assert.False(t, blocked)
}

func TestHandleTagMutability_Block_Returns403(t *testing.T) {
	adapter.ClearHeadCache()

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Insert an artifact with a known SHA256.
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"pypi:testpkg:1.0.0", "pypi", "testpkg", "1.0.0", "http://example.com/pkg", "old-sha256", 100,
		time.Now().UTC(), time.Now().UTC(), "/tmp/test",
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status) VALUES (?, ?)`,
		"pypi:testpkg:1.0.0", "CLEAN",
	)
	require.NoError(t, err)

	// Upstream returns a different ETag.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"new-etag"`)
		w.Header().Set("Content-Length", "200")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.TagMutabilityConfig{
		Enabled:         true,
		Action:          "block",
		CheckOnCacheHit: true,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	blocked := adapter.HandleTagMutability(context.Background(), cfg, db, &http.Client{},
		"pypi", "testpkg", "1.0.0", "pypi:testpkg:1.0.0", srv.URL+"/pkg", r, w)
	assert.True(t, blocked)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleTagMutability_Warn_ServesNormally(t *testing.T) {
	adapter.ClearHeadCache()

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Insert an artifact.
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"pypi:warnpkg:1.0.0", "pypi", "warnpkg", "1.0.0", "http://example.com/pkg", "old-sha256", 100,
		time.Now().UTC(), time.Now().UTC(), "/tmp/test",
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status) VALUES (?, ?)`,
		"pypi:warnpkg:1.0.0", "CLEAN",
	)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"changed-etag"`)
		w.Header().Set("Content-Length", "300")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.TagMutabilityConfig{
		Enabled:         true,
		Action:          "warn",
		CheckOnCacheHit: true,
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	blocked := adapter.HandleTagMutability(context.Background(), cfg, db, &http.Client{},
		"pypi", "warnpkg", "1.0.0", "pypi:warnpkg:1.0.0", srv.URL+"/pkg", r, w)
	assert.False(t, blocked, "warn action should not block")

	// Verify audit log was written.
	var count int
	err = db.Get(&count, "SELECT COUNT(*) FROM audit_log WHERE event_type = 'TAG_MUTATED' AND artifact_id = 'pypi:warnpkg:1.0.0'")
	require.NoError(t, err)
	assert.Equal(t, 1, count, "TAG_MUTATED audit entry should exist")

	// Verify digest history was recorded.
	err = db.Get(&count, "SELECT COUNT(*) FROM tag_digest_history WHERE ecosystem = 'pypi' AND name = 'warnpkg'")
	require.NoError(t, err)
	assert.Equal(t, 1, count, "digest history should be recorded")
}

func TestCheckDigestChanged_UnknownEcosystem_NoChange(t *testing.T) {
	adapter.ClearHeadCache()
	changed, _, err := adapter.CheckDigestChanged(context.Background(), "unknown", "http://example.com", "sha256", &http.Client{})
	require.NoError(t, err)
	assert.False(t, changed)
}
