package docker_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// errBackend is a cache.BlobStore whose read paths return a transport-style error
// (NOT cache.ErrBlobNotFound), to exercise the fail-closed serve path.
type errBackend struct{}

func (errBackend) PutBlob(context.Context, string, []byte) error { return nil }
func (errBackend) GetBlob(context.Context, string) ([]byte, error) {
	return nil, errors.New("transport boom")
}
func (errBackend) DeleteBlob(context.Context, string) error { return nil }
func (errBackend) StatBlob(context.Context, string) (int64, error) {
	return 0, errors.New("transport boom")
}
func (errBackend) GetBlobStream(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, errors.New("transport boom")
}

func newServeTestAdapter(t *testing.T, blobStore *docker.BlobStore) (*docker.DockerAdapter, *config.GateDB) {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)
	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://upstream.invalid", // must never be reached on these paths
		Push:            config.DockerPushConfig{Enabled: true},
	}
	a := docker.NewDockerAdapterWithPush(db, cacheStore, scanEngine, policyEngine, cfg, blobStore)
	return a, db
}

func getBlob(a *docker.DockerAdapter, name, digest string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v2/"+name+"/blobs/"+digest, nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

// Security: a backend transport error on a KNOWN internal repo's referenced blob
// must fail closed (503), never fall through to the upstream registry.
func TestServeInternalBlob_BackendError_FailsClosedForKnownTag(t *testing.T) {
	bs := docker.NewBlobStore(errBackend{}, "docker-push")
	a, db := newServeTestAdapter(t, bs)

	repo, err := docker.EnsureRepository(db, "", "myteam/app", true)
	require.NoError(t, err)
	// Clean (non-quarantined) manifest references the layer → servable gate passes,
	// so the request reaches the backend read, which errors.
	require.NoError(t, docker.RecordBlobRefs(db, repo.ID, "docker:myteam_app:1.0", []string{"sha256:abc123"}))

	w := getBlob(a, "myteam/app", "sha256:abc123")
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "backend error must fail closed with 503, not proxy upstream")
}

// Security: a layer belonging to a QUARANTINED manifest must not be servable by
// digest (404), closing the pre-existing serveInternalBlob quarantine bypass.
func TestServeInternalBlob_QuarantinedManifest_LayerNotServable(t *testing.T) {
	backend, err := local.NewLocalCacheStore(t.TempDir(), 0)
	require.NoError(t, err)
	bs := docker.NewBlobStore(backend, "docker-push")
	a, db := newServeTestAdapter(t, bs)

	// Store the layer bytes so absence is NOT the reason for the 404.
	require.NoError(t, bs.Put(context.Background(), "sha256:abc123", []byte("layer-bytes")))

	repo, err := docker.EnsureRepository(db, "", "myteam/app", true)
	require.NoError(t, err)
	artifactID := "docker:myteam_app:1.0"
	require.NoError(t, docker.RecordBlobRefs(db, repo.ID, artifactID, []string{"sha256:abc123"}))

	// Quarantine the only manifest referencing the layer.
	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'docker', 'myteam/app', '1.0', '', '', 0, ?, ?, '')`,
		artifactID, now, now,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, rescan_due_at)
		 VALUES (?, ?, ?, ?, ?)`,
		artifactID, string(model.StatusQuarantined), "malware", now, now.Add(time.Hour),
	)
	require.NoError(t, err)

	w := getBlob(a, "myteam/app", "sha256:abc123")
	require.Equal(t, http.StatusNotFound, w.Code, "quarantined manifest's layer must not be servable")
}

// A clean, referenced layer is streamed back with its bytes and length.
func TestServeInternalBlob_CleanLayer_StreamsBytes(t *testing.T) {
	backend, err := local.NewLocalCacheStore(t.TempDir(), 0)
	require.NoError(t, err)
	bs := docker.NewBlobStore(backend, "docker-push")
	a, db := newServeTestAdapter(t, bs)

	content := []byte("the streamed layer body")
	require.NoError(t, bs.Put(context.Background(), "sha256:abc123", content))

	repo, err := docker.EnsureRepository(db, "", "myteam/app", true)
	require.NoError(t, err)
	require.NoError(t, docker.RecordBlobRefs(db, repo.ID, "docker:myteam_app:1.0", []string{"sha256:abc123"}))

	w := getBlob(a, "myteam/app", "sha256:abc123")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, content, w.Body.Bytes())
	require.Equal(t, "sha256:abc123", w.Header().Get("Docker-Content-Digest"))
}

// An unknown blob in a known internal repo must 404 (not fall through to upstream).
func TestServeInternalBlob_UnreferencedBlob_NotServable(t *testing.T) {
	backend, err := local.NewLocalCacheStore(t.TempDir(), 0)
	require.NoError(t, err)
	bs := docker.NewBlobStore(backend, "docker-push")
	a, db := newServeTestAdapter(t, bs)

	_, err = docker.EnsureRepository(db, "", "myteam/app", true)
	require.NoError(t, err)
	// No refs recorded → the blob is not referenced by any clean manifest.

	w := getBlob(a, "myteam/app", "sha256:abc123")
	require.Equal(t, http.StatusNotFound, w.Code)
}

var _ cache.BlobStore = errBackend{}
