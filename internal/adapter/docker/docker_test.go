package docker_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func setupTestDocker(t *testing.T, upstreamHandler http.HandlerFunc) (*docker.DockerAdapter, *httptest.Server, *sqlx.DB, *local.LocalCacheStore) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL)
	return a, upstream, db, cacheStore
}

func TestDockerAdapter_Ecosystem_ReturnsDocker(t *testing.T) {
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, scanner.EcosystemDocker, a.Ecosystem())
}

func TestDockerAdapter_V2Check_Returns200WithHeader(t *testing.T) {
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upstream.Close()

	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
}

func TestDockerAdapter_Manifest_UncachedImage_Returns502WhenCraneFails(t *testing.T) {
	// A simple mock HTTP server is not a valid OCI registry, so crane.Pull
	// will fail. The adapter should return 502 in this case.
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// crane.Pull fails against mock → 502
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestDockerAdapter_Manifest_CachedClean_ServesFromCache(t *testing.T) {
	a, _, db, cacheStore := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for cached manifests")
	})

	artifactID := "docker:library_alpine:3.20"
	manifestContent := `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`

	// Pre-populate cache: write manifest file and insert DB records.
	art := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      "library_alpine",
		Version:   "3.20",
	}
	tmpFile := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(manifestContent), 0644))
	require.NoError(t, cacheStore.Put(nil, art, tmpFile))

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT OR REPLACE INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, "docker", "library/alpine", "3.20", "https://registry-1.docker.io/v2/library/alpine/manifests/3.20",
		"abc123", len(manifestContent), now, now, tmpFile,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT OR REPLACE INTO artifact_status (artifact_id, status, quarantine_reason, rescan_due_at)
		 VALUES (?, ?, '', ?)`,
		artifactID, string(model.StatusClean), now.Add(168*time.Hour),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v2/library/alpine/manifests/3.20", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "schemaVersion")
	assert.Equal(t, "true", w.Header().Get("X-Shieldoo-Scanned"))
}

func TestDockerAdapter_Manifest_QuarantinedImage_Returns403(t *testing.T) {
	a, _, db, cacheStore := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for quarantined manifests")
	})

	artifactID := "docker:library_malicious:latest"

	// Pre-populate cache with quarantined image.
	art := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      "library_malicious",
		Version:   "latest",
	}
	tmpFile := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(`{"schemaVersion":2}`), 0644))
	require.NoError(t, cacheStore.Put(nil, art, tmpFile))

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT OR REPLACE INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, "docker", "library/malicious", "latest", "", "abc", 10, now, now, tmpFile,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT OR REPLACE INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, rescan_due_at)
		 VALUES (?, ?, ?, ?, ?)`,
		artifactID, string(model.StatusQuarantined), "malicious image detected", now, now.Add(168*time.Hour),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v2/library/malicious/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "quarantined")
}

func TestDockerAdapter_Blob_ProxiesUpstream(t *testing.T) {
	blobContent := []byte("fake layer blob data")

	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
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
