package docker_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func headManifest(a *docker.DockerAdapter, name, ref string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodHead, "/v2/"+name+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

func getManifest(a *docker.DockerAdapter, name, ref string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v2/"+name+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	return w
}

// Regression for the v0.12.0 docker-push break: HEAD /manifests/{ref} for an
// internally-pushed image MUST be served from the durable BlobStore, NOT proxied
// to the upstream registry. The classic/containerd push client issues a manifest
// HEAD as an existence check; proxying it upstream leaked an upstream 401 that
// aborted `docker push` (and broke pulls of pushed images). The serve adapter's
// DefaultRegistry is unreachable, so any upstream proxy attempt fails the test.
func TestHEADManifest_InternalPushedImage_ServedFromStore(t *testing.T) {
	backend, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)
	bs := docker.NewBlobStore(backend, "docker-push")
	a, db := newServeTestAdapter(t, bs)

	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`)
	sum := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	require.NoError(t, bs.Put(context.Background(), digest, manifest))

	repo, err := docker.EnsureRepository(db, "", "myteam/app", true)
	require.NoError(t, err)
	// docker_tags.artifact_id is an FK to artifacts(id); seed the row first.
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"docker:myteam_app:v1", "docker", "myteam/app", "v1", "internal://myteam/app", digest[7:], len(manifest),
		time.Now().UTC(), time.Now().UTC(), "")
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1", digest, "docker:myteam_app:v1"))

	w := headManifest(a, "myteam/app", "v1")
	require.Equal(t, http.StatusOK, w.Code,
		"HEAD of an internally-pushed manifest must serve from the durable store, not proxy upstream")
	require.Equal(t, digest, w.Header().Get("Docker-Content-Digest"))
	require.Equal(t, "true", w.Header().Get("X-Shieldoo-Scanned"))
}

// docker pull resolves a tag, then re-fetches/verifies the manifest BY DIGEST.
// Internal manifests must therefore resolve by digest too — not only by tag —
// otherwise the by-digest probe falls through to upstream and breaks the pull of
// a pushed image. Covers both HEAD and GET.
func TestManifest_InternalPushedImage_ResolvableByDigest(t *testing.T) {
	backend, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)
	bs := docker.NewBlobStore(backend, "docker-push")
	a, db := newServeTestAdapter(t, bs)

	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	sum := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	require.NoError(t, bs.Put(context.Background(), digest, manifest))

	repo, err := docker.EnsureRepository(db, "", "myteam/app", true)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"docker:myteam_app:v1", "docker", "myteam/app", "v1", "internal://myteam/app", digest[7:], len(manifest),
		time.Now().UTC(), time.Now().UTC(), "")
	require.NoError(t, err)
	// Only a NAMED tag is stored; the request comes in by DIGEST.
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1", digest, "docker:myteam_app:v1"))

	hw := headManifest(a, "myteam/app", digest)
	require.Equal(t, http.StatusOK, hw.Code, "HEAD by digest must resolve the internally-pushed manifest")
	require.Equal(t, digest, hw.Header().Get("Docker-Content-Digest"))

	gw := getManifest(a, "myteam/app", digest)
	require.Equal(t, http.StatusOK, gw.Code, "GET by digest must resolve the internally-pushed manifest")
	require.Equal(t, manifest, gw.Body.Bytes())
}

// During the first push of a brand-new internal image, the push client HEADs the
// manifest before PUT. The repo is not yet internal (it is created at PUT time),
// so the HEAD falls through to the upstream registry, which returns 401/403 for
// the unknown/private name. The gate never forwards client creds upstream, so it
// cannot serve that name anyway — an upstream auth error on a push-allowed name
// MUST be mapped to 404 ("not present here") so the push client proceeds to PUT.
func TestHEADManifest_PushAllowed_UpstreamForbidden_MapsTo404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate Docker Hub denying access to an unknown/private repo.
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)
	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	bs := docker.NewBlobStore(cacheStore, "docker-push")
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: upstream.URL,
		Push:            config.DockerPushConfig{Enabled: true},
	}
	a := docker.NewDockerAdapterWithPush(db, cacheStore, scanEngine, policyEngine, cfg, bs)

	w := headManifest(a, "myteam/newapp", "v1")
	require.Equal(t, http.StatusNotFound, w.Code,
		"push-allowed name with upstream auth error must map to 404 so docker push can proceed")
}

// A pull-through HEAD for a push-allowed name that genuinely exists upstream must
// still succeed (200) — the 401/403→404 mapping is limited to upstream auth errors.
func TestHEADManifest_PushAllowed_UpstreamOK_Forwards200(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodHead, r.Method)
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("Docker-Content-Digest", "sha256:deadbeef")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)
	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	bs := docker.NewBlobStore(cacheStore, "docker-push")
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: upstream.URL,
		Push:            config.DockerPushConfig{Enabled: true},
	}
	a := docker.NewDockerAdapterWithPush(db, cacheStore, scanEngine, policyEngine, cfg, bs)

	w := headManifest(a, "myteam/upstreamapp", "latest")
	require.Equal(t, http.StatusOK, w.Code, "existing upstream manifest must still be HEAD-able through the gate")
}
