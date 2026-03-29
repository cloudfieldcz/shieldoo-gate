package docker_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func setupTestDockerWithPush(t *testing.T) *docker.DockerAdapter {
	t.Helper()

	db, err := config.InitDB(config.SQLiteMemoryConfig())
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

	blobDir := t.TempDir()
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: "https://ghcr.io"},
		},
		Push: config.DockerPushConfig{Enabled: true},
	}
	blobStore := docker.NewBlobStore(blobDir)
	return docker.NewDockerAdapterWithPush(db, cacheStore, scanEngine, policyEngine, cfg, blobStore)
}

func TestDockerPush_UpstreamNamespace_Returns403(t *testing.T) {
	a := setupTestDockerWithPush(t)
	req := httptest.NewRequest(http.MethodPost, "/v2/ghcr.io/user/app/blobs/uploads/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDockerPush_InitiateUpload_Returns202(t *testing.T) {
	a := setupTestDockerWithPush(t)
	req := httptest.NewRequest(http.MethodPost, "/v2/myteam/myapp/blobs/uploads/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.NotEmpty(t, w.Header().Get("Location"))
	assert.NotEmpty(t, w.Header().Get("Docker-Upload-UUID"))
}

func TestDockerPush_CompleteUpload_Returns201(t *testing.T) {
	a := setupTestDockerWithPush(t)

	// Step 1: Initiate
	initReq := httptest.NewRequest(http.MethodPost, "/v2/myteam/myapp/blobs/uploads/", nil)
	initW := httptest.NewRecorder()
	a.ServeHTTP(initW, initReq)
	require.Equal(t, http.StatusAccepted, initW.Code)
	location := initW.Header().Get("Location")

	// Step 2: Complete with digest
	blobData := []byte("fake blob content")
	h := sha256.Sum256(blobData)
	digest := "sha256:" + hex.EncodeToString(h[:])

	completeReq := httptest.NewRequest(http.MethodPut, location+"?digest="+digest, bytes.NewReader(blobData))
	completeW := httptest.NewRecorder()
	a.ServeHTTP(completeW, completeReq)
	assert.Equal(t, http.StatusCreated, completeW.Code)
	assert.Equal(t, digest, completeW.Header().Get("Docker-Content-Digest"))
}

func TestDockerPush_CompleteUpload_DigestMismatch_Returns400(t *testing.T) {
	a := setupTestDockerWithPush(t)

	// Initiate
	initReq := httptest.NewRequest(http.MethodPost, "/v2/myteam/myapp/blobs/uploads/", nil)
	initW := httptest.NewRecorder()
	a.ServeHTTP(initW, initReq)
	require.Equal(t, http.StatusAccepted, initW.Code)
	location := initW.Header().Get("Location")

	// Complete with wrong digest
	blobData := []byte("some data")
	completeReq := httptest.NewRequest(http.MethodPut, location+"?digest=sha256:0000000000000000000000000000000000000000000000000000000000000000", bytes.NewReader(blobData))
	completeW := httptest.NewRecorder()
	a.ServeHTTP(completeW, completeReq)
	assert.Equal(t, http.StatusBadRequest, completeW.Code)
}

func TestDockerPush_BlobHead_ExistingBlob_Returns200(t *testing.T) {
	a := setupTestDockerWithPush(t)

	// Step 1: Upload a blob
	initReq := httptest.NewRequest(http.MethodPost, "/v2/myteam/myapp/blobs/uploads/", nil)
	initW := httptest.NewRecorder()
	a.ServeHTTP(initW, initReq)
	require.Equal(t, http.StatusAccepted, initW.Code)
	location := initW.Header().Get("Location")

	blobData := []byte("blob for head test")
	h := sha256.Sum256(blobData)
	digest := "sha256:" + hex.EncodeToString(h[:])

	completeReq := httptest.NewRequest(http.MethodPut, location+"?digest="+digest, bytes.NewReader(blobData))
	completeW := httptest.NewRecorder()
	a.ServeHTTP(completeW, completeReq)
	require.Equal(t, http.StatusCreated, completeW.Code)

	// Step 2: HEAD the blob
	headReq := httptest.NewRequest(http.MethodHead, "/v2/myteam/myapp/blobs/"+digest, nil)
	headW := httptest.NewRecorder()
	a.ServeHTTP(headW, headReq)
	assert.Equal(t, http.StatusOK, headW.Code)
	assert.Equal(t, digest, headW.Header().Get("Docker-Content-Digest"))
}

func TestDockerPush_BlobHead_NonExisting_Returns404(t *testing.T) {
	a := setupTestDockerWithPush(t)

	headReq := httptest.NewRequest(http.MethodHead, "/v2/myteam/myapp/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil)
	headW := httptest.NewRecorder()
	a.ServeHTTP(headW, headReq)
	assert.Equal(t, http.StatusNotFound, headW.Code)
}

func TestDockerPush_ManifestPut_ScansBeforeResponse(t *testing.T) {
	// Push a manifest → adapter must scan before returning 201.
	// With no scanners configured, scan returns clean → 201.
	a := setupTestDockerWithPush(t)

	manifestBody := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`)
	req := httptest.NewRequest(http.MethodPut, "/v2/myteam/myapp/manifests/v1.0", bytes.NewReader(manifestBody))
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotEmpty(t, w.Header().Get("Docker-Content-Digest"))
}

func TestDockerPush_ManifestPut_UpstreamNamespace_Returns403(t *testing.T) {
	a := setupTestDockerWithPush(t)

	manifestBody := []byte(`{"schemaVersion":2}`)
	req := httptest.NewRequest(http.MethodPut, "/v2/ghcr.io/user/app/manifests/latest", bytes.NewReader(manifestBody))
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDockerPush_ManifestPut_CreatesTag(t *testing.T) {
	a := setupTestDockerWithPush(t)

	manifestBody := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`)

	// Push v1.0
	req := httptest.NewRequest(http.MethodPut, "/v2/myteam/myapp/manifests/v1.0", bytes.NewReader(manifestBody))
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	digest := w.Header().Get("Docker-Content-Digest")
	assert.Contains(t, digest, "sha256:")

	// Push same manifest with different tag
	req2 := httptest.NewRequest(http.MethodPut, "/v2/myteam/myapp/manifests/latest", bytes.NewReader(manifestBody))
	req2.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	w2 := httptest.NewRecorder()
	a.ServeHTTP(w2, req2)

	require.Equal(t, http.StatusCreated, w2.Code)
	// Same manifest → same digest
	assert.Equal(t, digest, w2.Header().Get("Docker-Content-Digest"))
}

func TestDockerPush_Disabled_Returns403(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)

	// Push NOT enabled
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		Push:            config.DockerPushConfig{Enabled: false},
	}
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)

	req := httptest.NewRequest(http.MethodPost, "/v2/myteam/myapp/blobs/uploads/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
