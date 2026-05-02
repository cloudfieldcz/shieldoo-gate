package maven_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/maven"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
)

// setupTestMavenWithTyposquat builds a Maven adapter wired with the real
// builtin typosquat scanner (no policy override DB).
func setupTestMavenWithTyposquat(t *testing.T, upstreamHandler http.HandlerFunc) (*maven.MavenAdapter, *httptest.Server) {
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
	return maven.NewMavenAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, nil), upstream
}

// setupTestMavenOverrideAware wires the typosquat scanner AND the policy
// engine against a shared in-memory DB so HasOverride() can read
// policy_overrides. Returns the adapter, upstream, and DB.
func setupTestMavenOverrideAware(t *testing.T, upstreamHandler http.HandlerFunc) (*maven.MavenAdapter, *httptest.Server, *config.GateDB) {
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
	a := maven.NewMavenAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, nil)
	return a, upstream, db
}

// TestMavenAdapter_TyposquatBlocks_JarFetch_Returns403 verifies that a
// typosquat groupId:artifactId (close to a popular Maven coordinate) is
// blocked at the JAR fetch endpoint, before any upstream call.
func TestMavenAdapter_TyposquatBlocks_JarFetch_Returns403(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestMavenWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	// "com.google.guava:guave" is ed=1 from "com.google.guava:guava" — a clear typosquat.
	req := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guave/32.0.1-jre/guave-32.0.1-jre.jar", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"typosquat must be blocked before contacting upstream")
	assert.False(t, upstreamHit,
		"upstream must not be reached for blocked typosquat")
	assert.Contains(t, w.Body.String(), "typosquatting detected")
}

// TestMavenAdapter_TyposquatBlock_PersistsArtifactRow verifies that a 403'd
// typosquat coordinate produces a synthetic 4-segment artifact row with
// version="*" so admins can manage it from the Artifacts pane.
func TestMavenAdapter_TyposquatBlock_PersistsArtifactRow(t *testing.T) {
	a, _, db := setupTestMavenOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be reached for blocked typosquat")
	})

	req := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guave/32.0.1-jre/guave-32.0.1-jre.jar", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)

	// Maven artifact IDs are 4-segment: maven:groupId:artifactId:*
	artifactID := "maven:com.google.guava:guave:*"

	var name, version string
	require.NoError(t, db.QueryRow(`SELECT name, version FROM artifacts WHERE id = ?`, artifactID).Scan(&name, &version))
	assert.Equal(t, "com.google.guava:guave", name)
	assert.Equal(t, "*", version, "typosquat synthetic rows always carry version=*")

	var status, reason string
	require.NoError(t, db.QueryRow(`SELECT status, COALESCE(quarantine_reason,'') FROM artifact_status WHERE artifact_id = ?`, artifactID).Scan(&status, &reason))
	assert.Equal(t, "QUARANTINED", status)
	assert.Contains(t, reason, "typosquat")

	var scannerName string
	require.NoError(t, db.QueryRow(`SELECT scanner_name FROM scan_results WHERE artifact_id = ?`, artifactID).Scan(&scannerName))
	assert.Equal(t, "builtin-typosquat", scannerName)
}

// TestMavenAdapter_TyposquatOverride_PackageScopeOverride verifies that an
// active package-scoped override on the maven coordinate suppresses the
// typosquat block and lets the JAR request reach upstream.
func TestMavenAdapter_TyposquatOverride_PackageScopeOverride(t *testing.T) {
	upstreamHit := false
	a, _, db := setupTestMavenOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/java-archive")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake jar"))
	})

	now := time.Now().UTC()
	res, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('maven', 'com.google.guava:guave', '', 'package', 'manual release', 'test', ?, 0)`, now)
	require.NoError(t, err)
	overrideID, err := res.LastInsertId()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guave/32.0.1-jre/guave-32.0.1-jre.jar", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "package-scope override must suppress typosquat block")
	assert.True(t, upstreamHit, "request must reach upstream after override")

	// EVENT_SERVED audit entry includes override_id in metadata_json.
	var metadataJSON string
	err = db.QueryRow(
		`SELECT COALESCE(metadata_json,'') FROM audit_log
		  WHERE artifact_id = ? AND event_type = 'SERVED'
		  ORDER BY id DESC LIMIT 1`,
		"maven:com.google.guava:guave:*",
	).Scan(&metadataJSON)
	require.NoError(t, err)
	assert.Contains(t, metadataJSON, fmt.Sprintf(`"override_id":%d`, overrideID),
		"audit metadata must record the exact override_id that allowed the request through")
}

// TestMavenAdapter_LegitimateCoordinate_NotBlocked is the positive control:
// a real popular coordinate (com.google.guava:guava) must NOT be blocked by
// Strategy 1 (exact-match short-circuit).
func TestMavenAdapter_LegitimateCoordinate_NotBlocked(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestMavenWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/java-archive")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake jar"))
	})

	req := httptest.NewRequest(http.MethodGet,
		"/com/google/guava/guava/32.0.1-jre/guava-32.0.1-jre.jar", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"legitimate coordinate must not be blocked by typosquat pre-scan")
	assert.True(t, upstreamHit)
}
