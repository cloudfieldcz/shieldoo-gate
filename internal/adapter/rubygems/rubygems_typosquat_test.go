package rubygems_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/rubygems"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
)

func setupTestRubyGemsWithTyposquat(t *testing.T, upstreamHandler http.HandlerFunc) (*rubygems.RubyGemsAdapter, *httptest.Server) {
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
	return rubygems.NewRubyGemsAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL), upstream
}

func setupTestRubyGemsOverrideAware(t *testing.T, upstreamHandler http.HandlerFunc) (*rubygems.RubyGemsAdapter, *httptest.Server, *config.GateDB) {
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
	a := rubygems.NewRubyGemsAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL)
	return a, upstream, db
}

// TestRubyGemsAdapter_TyposquatBlocks_GemDownload_Returns403 verifies that a
// typosquat gem name (close to a popular Gem) is blocked at the .gem download
// endpoint, before any upstream call.
func TestRubyGemsAdapter_TyposquatBlocks_GemDownload_Returns403(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestRubyGemsWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	// "railz" is ed=1 from "rails" — a clear typosquat.
	req := httptest.NewRequest(http.MethodGet, "/gems/railz-7.1.3.gem", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"typosquat must be blocked before contacting upstream")
	assert.False(t, upstreamHit,
		"upstream must not be reached for blocked typosquat")
	assert.Contains(t, w.Body.String(), "typosquatting detected")
}

// TestRubyGemsAdapter_TyposquatBlock_PersistsArtifactRow verifies that a 403'd
// typosquat name produces a synthetic artifacts/artifact_status/scan_results
// triple with version="*" so admins can manage it from the Artifacts pane.
//
// Note: full RubyGems artifact IDs are 4-segment (rubygems:name:version:filename),
// but typosquat synthetic rows always carry version="*" and an empty filename
// segment per Phase 0 decision C — the synthetic ID is rubygems:name:*.
func TestRubyGemsAdapter_TyposquatBlock_PersistsArtifactRow(t *testing.T) {
	a, _, db := setupTestRubyGemsOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be reached for blocked typosquat")
	})

	req := httptest.NewRequest(http.MethodGet, "/gems/railz-7.1.3.gem", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)

	artifactID := "rubygems:railz:*"

	var name, version string
	require.NoError(t, db.QueryRow(`SELECT name, version FROM artifacts WHERE id = ?`, artifactID).Scan(&name, &version))
	assert.Equal(t, "railz", name)
	assert.Equal(t, "*", version, "typosquat synthetic rows always carry version=*")

	var status, reason string
	require.NoError(t, db.QueryRow(`SELECT status, COALESCE(quarantine_reason,'') FROM artifact_status WHERE artifact_id = ?`, artifactID).Scan(&status, &reason))
	assert.Equal(t, "QUARANTINED", status)
	assert.Contains(t, reason, "typosquat")

	var scannerName string
	require.NoError(t, db.QueryRow(`SELECT scanner_name FROM scan_results WHERE artifact_id = ?`, artifactID).Scan(&scannerName))
	assert.Equal(t, "builtin-typosquat", scannerName)
}

// TestRubyGemsAdapter_TyposquatOverride_PackageScopeOverride verifies an
// active package-scoped override suppresses the typosquat block and lets the
// .gem fetch reach upstream.
func TestRubyGemsAdapter_TyposquatOverride_PackageScopeOverride(t *testing.T) {
	upstreamHit := false
	a, _, db := setupTestRubyGemsOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake gem content"))
	})

	now := time.Now().UTC()
	res, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('rubygems', 'railz', '', 'package', 'manual release', 'test', ?, 0)`, now)
	require.NoError(t, err)
	overrideID, err := res.LastInsertId()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/gems/railz-7.1.3.gem", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "package-scope override must suppress typosquat block")
	assert.True(t, upstreamHit, "request must reach upstream after override")

	var metadataJSON string
	err = db.QueryRow(
		`SELECT COALESCE(metadata_json,'') FROM audit_log
		  WHERE artifact_id = ? AND event_type = 'SERVED'
		  ORDER BY id DESC LIMIT 1`,
		"rubygems:railz:*",
	).Scan(&metadataJSON)
	require.NoError(t, err)
	assert.Contains(t, metadataJSON, fmt.Sprintf(`"override_id":%d`, overrideID),
		"audit metadata must record the exact override_id that allowed the request through")
}

// TestRubyGemsAdapter_LegitimateGem_NotBlocked is the positive control:
// rails (in seed) must not be blocked by typosquat pre-scan.
func TestRubyGemsAdapter_LegitimateGem_NotBlocked(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestRubyGemsWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake gem content"))
	})

	req := httptest.NewRequest(http.MethodGet, "/gems/rails-7.1.3.gem", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"legitimate gem must not be blocked by typosquat pre-scan")
	assert.True(t, upstreamHit)
}
