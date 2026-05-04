package docker_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func setupTestDocker(t *testing.T, upstreamHandler http.HandlerFunc) (*docker.DockerAdapter, *httptest.Server, *config.GateDB, *local.LocalCacheStore) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: upstream.URL,
	}
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)
	return a, upstream, db, cacheStore
}

func TestDockerAdapter_Ecosystem_ReturnsDocker(t *testing.T) {
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, scanner.EcosystemDocker, a.Ecosystem())
}

func TestDockerAdapter_V2Check_Returns200WithHeader(t *testing.T) {
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for /v2/ check")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
}

func TestDockerAdapter_V2Check_NoUpstream_StillReturnsHeader(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "http://does-not-exist.invalid",
	}
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)

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

	artifactID := "docker:docker_io_library_alpine:3.20"
	manifestContent := `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`

	// Pre-populate cache: write manifest file and insert DB records.
	art := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      "docker_io_library_alpine",
		Version:   "3.20",
	}
	tmpFile := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(manifestContent), 0644))
	require.NoError(t, cacheStore.Put(nil, art, tmpFile))

	// Compute real SHA256 of manifest content for integrity verification.
	manifestSHA := sha256.Sum256([]byte(manifestContent))
	manifestSHAHex := hex.EncodeToString(manifestSHA[:])

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, "docker", "library/alpine", "3.20", "https://registry-1.docker.io/v2/library/alpine/manifests/3.20",
		manifestSHAHex, len(manifestContent), now, now, tmpFile,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, rescan_due_at)
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

	artifactID := "docker:docker_io_library_malicious:latest"

	// Pre-populate cache with quarantined image.
	art := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      "docker_io_library_malicious",
		Version:   "latest",
	}
	tmpFile := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(`{"schemaVersion":2}`), 0644))
	require.NoError(t, cacheStore.Put(nil, art, tmpFile))

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, "docker", "library/malicious", "latest", "", "abc", 10, now, now, tmpFile,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, rescan_due_at)
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

func TestDockerAdapter_DisallowedRegistry_Returns403(t *testing.T) {
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for disallowed registries")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/evil.io/malware/pkg/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "not allowed")
}

func setupTestDockerMultiUpstream(t *testing.T, defaultHandler, ghcrHandler http.HandlerFunc) *docker.DockerAdapter {
	t.Helper()
	defaultUpstream := httptest.NewServer(defaultHandler)
	t.Cleanup(defaultUpstream.Close)
	ghcrUpstream := httptest.NewServer(ghcrHandler)
	t.Cleanup(ghcrUpstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)

	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: defaultUpstream.URL,
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: ghcrUpstream.URL},
		},
	}
	return docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)
}

func TestDockerAdapter_AllowedRegistry_BlobRoutesToCorrectUpstream(t *testing.T) {
	ghcrBlobContent := []byte("ghcr blob data")

	a := setupTestDockerMultiUpstream(t,
		func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("default upstream should not be called for ghcr.io images")
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ghcrBlobContent)
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/v2/ghcr.io/myuser/myapp/blobs/sha256:abc123", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, ghcrBlobContent, w.Body.Bytes())
}

func TestDockerAdapter_BareImageName_ExpandsToLibrary(t *testing.T) {
	var receivedPath string
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("blob"))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/nginx/blobs/sha256:abc123", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/v2/library/nginx/blobs/sha256:abc123", receivedPath)
}

// TestDockerAdapter_Manifest_Cached_OCIIndex_PreservesContentType pins Bug 1:
// cached manifests must report the actual mediaType from the body, not a
// hardcoded docker.distribution.manifest.v2+json. The docker daemon parses
// the body according to Content-Type — getting it wrong breaks multi-arch
// pulls (the daemon reads an OCI index as a single-arch v2 manifest).
func TestDockerAdapter_Manifest_Cached_OCIIndex_PreservesContentType(t *testing.T) {
	a, _, db, cacheStore := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for cached manifests")
	})

	artifactID := "docker:docker_io_library_redis:8-alpine"
	manifestContent := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`

	art := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      "docker_io_library_redis",
		Version:   "8-alpine",
	}
	tmpFile := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(manifestContent), 0644))
	require.NoError(t, cacheStore.Put(nil, art, tmpFile))

	manifestSHA := sha256.Sum256([]byte(manifestContent))
	manifestSHAHex := hex.EncodeToString(manifestSHA[:])

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, "docker", "library/redis", "8-alpine", "https://registry-1.docker.io/v2/library/redis/manifests/8-alpine",
		manifestSHAHex, len(manifestContent), now, now, tmpFile,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, rescan_due_at)
		 VALUES (?, ?, '', ?)`,
		artifactID, string(model.StatusClean), now.Add(168*time.Hour),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v2/library/redis/manifests/8-alpine", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/vnd.oci.image.index.v1+json", w.Header().Get("Content-Type"),
		"cached manifest Content-Type must reflect the body's mediaType, not a hardcoded default")
}

// TestDockerAdapter_HEAD_Manifest_Cached_ReturnsHeadersNoBody pins Bug 2 for
// the cache-hit path: HEAD must return 200 with Docker-Content-Digest,
// Content-Type, and Content-Length set, but no body.
func TestDockerAdapter_HEAD_Manifest_Cached_ReturnsHeadersNoBody(t *testing.T) {
	a, _, db, cacheStore := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for cached manifest HEAD")
	})

	artifactID := "docker:docker_io_library_alpine:3.20"
	manifestContent := `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`

	art := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      "docker_io_library_alpine",
		Version:   "3.20",
	}
	tmpFile := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(manifestContent), 0644))
	require.NoError(t, cacheStore.Put(nil, art, tmpFile))

	manifestSHA := sha256.Sum256([]byte(manifestContent))
	manifestSHAHex := hex.EncodeToString(manifestSHA[:])

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, "docker", "library/alpine", "3.20", "", manifestSHAHex, len(manifestContent), now, now, tmpFile,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, rescan_due_at)
		 VALUES (?, ?, '', ?)`,
		artifactID, string(model.StatusClean), now.Add(168*time.Hour),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodHead, "/v2/library/alpine/manifests/3.20", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "HEAD on cached manifest must return 200 — docker daemon aborts pull on 404")
	assert.Equal(t, "application/vnd.docker.distribution.manifest.v2+json", w.Header().Get("Content-Type"))
	assert.Equal(t, "sha256:"+manifestSHAHex, w.Header().Get("Docker-Content-Digest"))
	assert.NotEmpty(t, w.Header().Get("Content-Length"))
	assert.Empty(t, w.Body.String(), "HEAD must not return a body")
}

// TestDockerAdapter_HEAD_Manifest_Quarantined_Returns403 pins that HEAD
// honors the quarantine gate the same way GET does.
func TestDockerAdapter_HEAD_Manifest_Quarantined_Returns403(t *testing.T) {
	a, _, db, cacheStore := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for quarantined manifest HEAD")
	})

	artifactID := "docker:docker_io_library_malicious:latest"
	art := scanner.Artifact{
		ID:        artifactID,
		Ecosystem: scanner.EcosystemDocker,
		Name:      "docker_io_library_malicious",
		Version:   "latest",
	}
	tmpFile := filepath.Join(t.TempDir(), "manifest.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte(`{"schemaVersion":2}`), 0644))
	require.NoError(t, cacheStore.Put(nil, art, tmpFile))

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, "docker", "library/malicious", "latest", "", "abc", 10, now, now, tmpFile,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, rescan_due_at)
		 VALUES (?, ?, ?, ?, ?)`,
		artifactID, string(model.StatusQuarantined), "test", now, now.Add(168*time.Hour),
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodHead, "/v2/library/malicious/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "HEAD must honor quarantine the same way GET does")
}

// TestDockerAdapter_HEAD_Manifest_Uncached_ProxiesUpstream pins that HEAD
// for an uncached manifest is proxied to the upstream registry — without
// triggering the scan pipeline (which runs on the follow-up GET). This is
// what unblocks `docker pull` for fresh images: the daemon needs the digest
// from HEAD before issuing GET.
func TestDockerAdapter_HEAD_Manifest_Uncached_ProxiesUpstream(t *testing.T) {
	manifestBody := []byte(`{"schemaVersion":2}`)
	upstreamDigest := "sha256:" + hex.EncodeToString(func() []byte { s := sha256.Sum256(manifestBody); return s[:] }())
	var receivedMethod, receivedPath string

	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("Docker-Content-Digest", upstreamDigest)
		w.Header().Set("Content-Length", "19")
		w.WriteHeader(http.StatusOK)
		// Real upstream returns no body for HEAD; mock follows suit.
	})

	req := httptest.NewRequest(http.MethodHead, "/v2/library/nginx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "HEAD on uncached manifest must proxy upstream — daemon needs digest before GET")
	assert.Equal(t, http.MethodHead, receivedMethod, "upstream call must use HEAD, not GET")
	assert.Equal(t, "/v2/library/nginx/manifests/latest", receivedPath)
	assert.Equal(t, upstreamDigest, w.Header().Get("Docker-Content-Digest"))
	assert.Empty(t, w.Body.String(), "HEAD response must have no body")
}
