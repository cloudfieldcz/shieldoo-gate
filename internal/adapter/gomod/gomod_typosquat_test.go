package gomod_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/gomod"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
)

func setupTestGoModWithTyposquat(t *testing.T, upstreamHandler http.HandlerFunc) (*gomod.GoModAdapter, *httptest.Server) {
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
	}, nil)
	return gomod.NewGoModAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL), upstream
}

func setupTestGoModOverrideAware(t *testing.T, upstreamHandler http.HandlerFunc) (*gomod.GoModAdapter, *httptest.Server, *config.GateDB) {
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
	a := gomod.NewGoModAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL)
	return a, upstream, db
}

// TestGoModAdapter_TyposquatBlocks_VersionInfo_Returns410 verifies that a
// typosquat module path is blocked at the .info endpoint with HTTP 410
// (Go module proxy convention).
func TestGoModAdapter_TyposquatBlocks_VersionInfo_Returns410(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestGoModWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	// "github.com/spf13/vipper" is ed=1 from "github.com/spf13/viper".
	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/vipper/@v/v1.0.0.info", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGone, w.Code,
		"typosquat must be blocked with 410 Gone on .info endpoint")
	assert.False(t, upstreamHit,
		"upstream must not be reached for blocked typosquat")
	assert.Contains(t, w.Body.String(), "typosquatting detected")
}

// TestGoModAdapter_TyposquatBlocks_GoMod_Returns410 verifies the .mod endpoint.
func TestGoModAdapter_TyposquatBlocks_GoMod_Returns410(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestGoModWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/vipper/@v/v1.0.0.mod", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGone, w.Code)
	assert.False(t, upstreamHit)
}

// TestGoModAdapter_TyposquatBlocks_ZipDownload_Returns410 verifies the .zip endpoint.
func TestGoModAdapter_TyposquatBlocks_ZipDownload_Returns410(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestGoModWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/vipper/@v/v1.0.0.zip", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusGone, w.Code)
	assert.False(t, upstreamHit)
}

// TestGoModAdapter_NoBlock_VersionList asserts that /@v/list (the name-only
// enumeration phase used by `go mod tidy`) is NOT gated by the typosquat
// pre-scan — keeps tidy fast and avoids breaking enumeration of legitimate
// names. (Decision B in the rollout plan.)
func TestGoModAdapter_NoBlock_VersionList(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestGoModWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("v1.0.0\n"))
	})

	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/vipper/@v/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"@v/list must pass through without typosquat pre-scan (decision B)")
	assert.True(t, upstreamHit)
}

// TestGoModAdapter_NoBlock_AtLatest asserts that /@latest is NOT gated by
// the typosquat pre-scan. (Decision B.)
func TestGoModAdapter_NoBlock_AtLatest(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestGoModWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Version":"v1.0.0"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/vipper/@latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"/@latest must pass through without typosquat pre-scan (decision B)")
	assert.True(t, upstreamHit)
}

// TestGoModAdapter_TyposquatBlock_PersistsArtifactRow verifies that a 410'd
// typosquat module produces a synthetic artifact row with the go: prefix and
// version="*" so admins can manage it from the Artifacts pane.
func TestGoModAdapter_TyposquatBlock_PersistsArtifactRow(t *testing.T) {
	a, _, db := setupTestGoModOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be reached for blocked typosquat")
	})

	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/vipper/@v/v1.0.0.zip", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusGone, w.Code)

	// Go ecosystem prefix is "go:", not "gomod:" (EcosystemGo = "go").
	artifactID := "go:github.com/spf13/vipper:*"

	var name, version string
	require.NoError(t, db.QueryRow(`SELECT name, version FROM artifacts WHERE id = ?`, artifactID).Scan(&name, &version))
	assert.Equal(t, "github.com/spf13/vipper", name)
	assert.Equal(t, "*", version)

	var status, reason string
	require.NoError(t, db.QueryRow(`SELECT status, COALESCE(quarantine_reason,'') FROM artifact_status WHERE artifact_id = ?`, artifactID).Scan(&status, &reason))
	assert.Equal(t, "QUARANTINED", status)
	assert.Contains(t, reason, "typosquat")
}

// TestGoModAdapter_TyposquatOverride_PackageScopeOverride verifies an active
// package-scoped override suppresses the typosquat block and lets the request
// pass through to upstream.
func TestGoModAdapter_TyposquatOverride_PackageScopeOverride(t *testing.T) {
	upstreamHit := false
	a, _, db := setupTestGoModOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake zip"))
	})

	now := time.Now().UTC()
	res, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('go', 'github.com/spf13/vipper', '', 'package', 'manual release', 'test', ?, 0)`, now)
	require.NoError(t, err)
	overrideID, err := res.LastInsertId()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/vipper/@v/v1.0.0.info", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "package-scope override must suppress typosquat block")
	assert.True(t, upstreamHit, "request must reach upstream after override")

	var metadataJSON string
	err = db.QueryRow(
		`SELECT COALESCE(metadata_json,'') FROM audit_log
		  WHERE artifact_id = ? AND event_type = 'SERVED'
		  ORDER BY id DESC LIMIT 1`,
		"go:github.com/spf13/vipper:*",
	).Scan(&metadataJSON)
	require.NoError(t, err)
	assert.Contains(t, metadataJSON, fmt.Sprintf(`"override_id":%d`, overrideID))
}

// TestGoModAdapter_LegitimateModule_NotBlocked is the positive control:
// github.com/spf13/viper (in seed) must not be blocked.
func TestGoModAdapter_LegitimateModule_NotBlocked(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestGoModWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake zip"))
	})

	req := httptest.NewRequest(http.MethodGet, "/github.com/spf13/viper/@v/v1.0.0.info", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"legitimate module must not be blocked by typosquat pre-scan")
	assert.True(t, upstreamHit)
}
