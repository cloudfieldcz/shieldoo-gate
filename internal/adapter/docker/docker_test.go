package docker_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func setupTestDocker(t *testing.T, upstreamHandler http.HandlerFunc) (*docker.DockerAdapter, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)
	return docker.NewDockerAdapter(db, cacheStore, policyEngine, upstream.URL), upstream
}

func TestDockerAdapter_Ecosystem_ReturnsDocker(t *testing.T) {
	a, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, scanner.EcosystemDocker, a.Ecosystem())
}

func TestDockerAdapter_V2Check_Returns200WithHeader(t *testing.T) {
	a, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
}

func TestDockerAdapter_V2Check_NoUpstream_StillReturnsHeader(t *testing.T) {
	// Use a server that immediately closes — simulate unreachable upstream.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upstream.Close() // close immediately

	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	a := docker.NewDockerAdapter(db, cacheStore, policyEngine, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
}

func TestDockerAdapter_Manifest_ProxiesUpstream(t *testing.T) {
	const manifestBody = `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`

	a, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(manifestBody))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "schemaVersion")
}

func TestDockerAdapter_Blob_ProxiesUpstream(t *testing.T) {
	blobContent := []byte("fake layer blob data")

	a, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(blobContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginx/blobs/sha256:abc123", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, blobContent, w.Body.Bytes())
}
