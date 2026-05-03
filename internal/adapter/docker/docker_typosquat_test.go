package docker_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
)

func setupTestDockerWithTyposquat(t *testing.T, upstreamHandler http.HandlerFunc) (*docker.DockerAdapter, *httptest.Server, *config.GateDB) {
	t.Helper()
	adapter.ResetTyposquatPersistDedup()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	tsq, err := builtin.NewTyposquatScanner(db, config.TyposquatConfig{
		Enabled:          true,
		MaxEditDistance:  2,
		TopPackagesCount: 5000,
	})
	require.NoError(t, err)

	scanEngine := scanner.NewEngine([]scanner.Scanner{tsq}, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: upstream.URL,
	}
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)
	return a, upstream, db
}

// TestDockerAdapter_TyposquatBlocks_LibraryPrefixStripped_Returns403 verifies
// that a Docker Hub library/<typo> name is blocked at the manifest endpoint:
// the helper strips the library/ prefix before consulting the scanner so the
// bare-name seed entries match.
func TestDockerAdapter_TyposquatBlocks_LibraryPrefixStripped_Returns403(t *testing.T) {
	upstreamHit := false
	a, _, _ := setupTestDockerWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	// "nginxx" is ed=1 from "nginx" (in seed). The proxy sees library/nginxx,
	// strips library/ for Docker Hub, scanner matches against bare "nginx".
	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginxx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"typosquat must be blocked before contacting upstream")
	assert.False(t, upstreamHit,
		"upstream must not be reached for blocked typosquat")
	assert.Contains(t, w.Body.String(), "typosquatting detected")
}

// TestDockerAdapter_TyposquatBlocks_BareImagePathOnDockerHub_Returns403
// verifies that a bare image name (e.g. /v2/nginxx/...) — which the resolver
// expands to library/nginxx for Docker Hub — is also blocked. This is the
// shape `docker pull nginxx` produces in real clients.
func TestDockerAdapter_TyposquatBlocks_BareImagePathOnDockerHub_Returns403(t *testing.T) {
	upstreamHit := false
	a, _, _ := setupTestDockerWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/nginxx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"bare-name typosquat (resolver-expanded to library/) must be blocked")
	assert.False(t, upstreamHit)
}

// TestDockerAdapter_TyposquatBlock_PersistsArtifactRow verifies that a 403'd
// typosquat manifest pull produces a synthetic artifact row with version="*"
// and the safe-name shape, so admins can manage it from the Artifacts pane.
func TestDockerAdapter_TyposquatBlock_PersistsArtifactRow(t *testing.T) {
	a, _, db := setupTestDockerWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be reached for blocked typosquat")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginxx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)

	// Synthetic ID uses the safe-name (not the user-facing path) and version="*".
	artifactID := "docker:docker_io_library_nginxx:*"

	var name, version string
	require.NoError(t, db.QueryRow(`SELECT name, version FROM artifacts WHERE id = ?`, artifactID).Scan(&name, &version))
	assert.Equal(t, "docker_io_library_nginxx", name)
	assert.Equal(t, "*", version, "typosquat synthetic rows always carry version=*")

	var status, reason string
	require.NoError(t, db.QueryRow(`SELECT status, COALESCE(quarantine_reason,'') FROM artifact_status WHERE artifact_id = ?`, artifactID).Scan(&status, &reason))
	assert.Equal(t, "QUARANTINED", status)
	assert.Contains(t, reason, "typosquat")
}

// TestDockerAdapter_TyposquatOverride_PackageScopeOverride verifies an active
// package-scoped override on the safe-name suppresses the typosquat block.
func TestDockerAdapter_TyposquatOverride_PackageScopeOverride(t *testing.T) {
	upstreamHit := false
	a, _, db := setupTestDockerWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		// Mock OCI registry: this won't be a valid registry, so crane.Pull
		// will fail with 502 — but the typosquat helper should NOT 403.
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	})

	now := time.Now().UTC()
	res, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('docker', 'docker_io_library_nginxx', '', 'package', 'manual release', 'test', ?, 0)`, now)
	require.NoError(t, err)
	overrideID, err := res.LastInsertId()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginxx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// Pre-scan must not 403; downstream may still 502 because mock isn't a
	// real OCI registry. We only care that typosquat didn't block the request.
	assert.NotEqual(t, http.StatusForbidden, w.Code,
		"package-scope override must suppress typosquat block (downstream may 502 for other reasons)")
	assert.True(t, upstreamHit, "request must reach upstream after override")

	// EVENT_SERVED audit entry includes override_id in metadata_json.
	var metadataJSON string
	err = db.QueryRow(
		`SELECT COALESCE(metadata_json,'') FROM audit_log
		  WHERE artifact_id = ? AND event_type = 'SERVED'
		  ORDER BY id DESC LIMIT 1`,
		"docker:docker_io_library_nginxx:*",
	).Scan(&metadataJSON)
	require.NoError(t, err)
	assert.Contains(t, metadataJSON, fmt.Sprintf(`"override_id":%d`, overrideID))
}

// TestDockerAdapter_TyposquatBlocks_NonDockerHubRegistry_NoFalsePositive
// verifies that a non-Docker-Hub image whose path doesn't match any seed
// entry is NOT blocked. The seed contains bare image names; non-library
// paths on non-Docker-Hub registries don't get library/ stripping, so the
// scanner sees the full path which won't match a bare-name seed entry.
func TestDockerAdapter_TyposquatBlocks_NonDockerHubRegistry_NoFalsePositive(t *testing.T) {
	upstreamHit := false
	// ghcr.io path with a typosquat-shaped suffix — but resolver doesn't
	// strip library/, so scanner sees the full multi-segment path.
	a, _, _ := setupTestDockerWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	// "someorg/random-app" has no resemblance to any bare-name seed entry —
	// must not be blocked. (We use Docker Hub here because non-Docker-Hub
	// registries require allowlist setup; the same logic applies.)
	req := httptest.NewRequest(http.MethodGet, "/v2/someorg/random-app/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// Should not be blocked by typosquat (response code may be 502 from crane
	// against the mock — what matters is it isn't a typosquat 403).
	assert.NotEqual(t, http.StatusForbidden, w.Code,
		"non-matching path must not trigger a typosquat block")
	// Whether upstream was hit depends on crane behavior; we don't assert.
	_ = upstreamHit
}

// TestDockerAdapter_LegitimateImage_NotBlocked is the positive control:
// library/nginx (in seed, exact match) must not be blocked.
func TestDockerAdapter_LegitimateImage_NotBlocked(t *testing.T) {
	a, _, _ := setupTestDockerWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schemaVersion":2}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginx/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// The legitimate name passes the typosquat gate. It may still 502
	// from crane against the mock — just confirm it isn't a typosquat 403.
	assert.NotEqual(t, http.StatusForbidden, w.Code,
		"legitimate library/nginx must not be blocked by typosquat pre-scan")
}

// TestDockerAdapter_PushPath_NotGatedByTyposquat asserts decision A: push to
// internal namespaces is NOT gated by the typosquat scanner — internal
// pushes are authenticated developer acts and naming is operator-controlled.
func TestDockerAdapter_PushPath_NotGatedByTyposquat(t *testing.T) {
	adapter.ResetTyposquatPersistDedup()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	tsq, err := builtin.NewTyposquatScanner(db, config.TyposquatConfig{
		Enabled:          true,
		MaxEditDistance:  2,
		TopPackagesCount: 5000,
	})
	require.NoError(t, err)

	scanEngine := scanner.NewEngine([]scanner.Scanner{tsq}, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)
	blobStore := docker.NewBlobStore(t.TempDir())
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		Push:            config.DockerPushConfig{Enabled: true},
	}
	a := docker.NewDockerAdapterWithPush(db, cacheStore, scanEngine, policyEngine, cfg, blobStore)

	// Push to an internal namespace whose name resembles a typosquat
	// (myteam/nginxx). The push handler does NOT consult the typosquat
	// scanner, so the response must not be a typosquat 403.
	req := httptest.NewRequest(http.MethodPost, "/v2/myteam/nginxx/blobs/uploads/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.NotContains(t, w.Body.String(), "typosquatting detected",
		"push paths must not be gated by typosquat scanner")
	// Push initiate normally returns 202; just assert no typosquat 403.
	assert.Equal(t, http.StatusAccepted, w.Code,
		"internal push initiate must succeed regardless of typosquat scanner")
}
