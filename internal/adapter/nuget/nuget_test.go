package nuget_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/nuget"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
)

func setupTestNuGet(t *testing.T, upstreamHandler http.HandlerFunc) (*nuget.NuGetAdapter, *httptest.Server) {
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
	return nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{}), upstream
}

func TestNuGetAdapter_Ecosystem_ReturnsNuGet(t *testing.T) {
	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, scanner.EcosystemNuGet, a.Ecosystem())
}

func TestNuGetAdapter_ServiceIndex_RewritesUpstreamURLs(t *testing.T) {
	var upstreamBase string

	a, upstream := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		// Simulate api.nuget.org returning absolute URLs referencing itself.
		body := `{"version":"3.0.0","resources":[{"@id":"` + upstreamBase + `/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"}]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	upstreamBase = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/v3/index.json", nil)
	req.Host = "proxy.example.com"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Upstream URL must be replaced with proxy host.
	assert.NotContains(t, body, upstreamBase, "upstream base URL must not appear in rewritten response")
	assert.Contains(t, body, "http://proxy.example.com/v3-flatcontainer/")
}

func TestNuGetAdapter_Registration_RewritesUpstreamURLs(t *testing.T) {
	var upstreamBase string

	a, upstream := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		body := `{"count":1,"items":[{"@id":"` + upstreamBase + `/v3/registration/newtonsoft.json/index.json"}]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	upstreamBase = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Json/index.json", nil)
	req.Host = "proxy.example.com"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, upstreamBase, "upstream base URL must not appear in rewritten response")
	assert.Contains(t, body, "http://proxy.example.com/v3/registration/newtonsoft.json/index.json")
}

func TestNuGetAdapter_NupkgDownload_CleanPackage_Serves200(t *testing.T) {
	fileContent := []byte("fake nupkg content")

	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// No scanners → policy defaults to clean → allow.
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestNuGetAdapter_Passthrough_RepositorySignatures_Returns200(t *testing.T) {
	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allRepositorySigned":false}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v3-index/repository-signatures/5.0.0/index.json", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "allRepositorySigned")
}

func TestNuGetAdapter_ServiceIndex_StripsRepositorySignatures_OverHTTP(t *testing.T) {
	var upstreamBase string

	a, upstream := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		body := `{"version":"3.0.0","resources":[` +
			`{"@id":"` + upstreamBase + `/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"},` +
			`{"@id":"` + upstreamBase + `/v3-index/repository-signatures/5.0.0/index.json","@type":"RepositorySignatures/5.0.0"}` +
			`]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	upstreamBase = upstream.URL

	// HTTP request (no TLS, no X-Forwarded-Proto) — RepositorySignatures must be stripped.
	req := httptest.NewRequest(http.MethodGet, "/v3/index.json", nil)
	req.Host = "proxy.example.com"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, "RepositorySignatures", "RepositorySignatures must be stripped over HTTP")
	assert.Contains(t, body, "PackageBaseAddress", "other resources must be preserved")
}

func TestNuGetAdapter_NupkgDownload_InvalidPackageID_Returns400(t *testing.T) {
	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use chi routing-safe but validation-unsafe name. The chi param won't
	// match shell metacharacters so we test with a dotted name that would pass
	// chi but force a validation to run.
	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Json/index.json", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	// Newtonsoft.Json is a valid package name — should proxy through.
	assert.Equal(t, http.StatusOK, w.Code)
}

// setupTestNuGetWithTyposquat builds a NuGet adapter wired with the real
// builtin typosquat scanner so PreScanTyposquat behaves like in production.
// Used for cases where no policy override is involved.
func setupTestNuGetWithTyposquat(t *testing.T, upstreamHandler http.HandlerFunc) (*nuget.NuGetAdapter, *httptest.Server) {
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
	return nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{}), upstream
}

// setupTestNuGetOverrideAware wires the typosquat scanner AND the policy
// engine against a shared in-memory DB so HasOverride() can read
// policy_overrides. Returns the adapter, upstream, and DB so tests can seed
// overrides and inspect synthetic typosquat-block rows.
func setupTestNuGetOverrideAware(t *testing.T, upstreamHandler http.HandlerFunc) (*nuget.NuGetAdapter, *httptest.Server, *config.GateDB) {
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
	a := nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{})
	return a, upstream, db
}

// TestNuGetAdapter_TyposquatBlocks_RegistrationLevel_Returns403 verifies that
// a typosquat package id (close to a popular NuGet package) is blocked at the
// /v3/registration/{id}/index.json metadata endpoint, before any upstream call.
func TestNuGetAdapter_TyposquatBlocks_RegistrationLevel_Returns403(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestNuGetWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	// "Newtonsoft.Jsom" is ed=1 from "Newtonsoft.Json" — a clear typosquat.
	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Jsom/index.json", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"typosquat must be blocked at registration before contacting upstream")
	assert.False(t, upstreamHit,
		"upstream must not be reached for blocked typosquat")
	assert.Contains(t, w.Body.String(), "typosquatting detected")
}

// TestNuGetAdapter_TyposquatBlocks_DownloadLevel_Returns403 verifies that the
// .nupkg download endpoint also blocks typosquat names before upstream fetch.
func TestNuGetAdapter_TyposquatBlocks_DownloadLevel_Returns403(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestNuGetWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v3-flatcontainer/Newtonsoft.Jsom/13.0.3/Newtonsoft.Jsom.13.0.3.nupkg", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, upstreamHit)
	assert.Contains(t, w.Body.String(), "typosquatting detected")
}

// TestNuGetAdapter_TyposquatBlock_PersistsArtifactRow verifies that a 403'd
// typosquat name produces a synthetic artifacts/artifact_status/scan_results
// triple with version="*" so admins can manage it from the Artifacts pane.
func TestNuGetAdapter_TyposquatBlock_PersistsArtifactRow(t *testing.T) {
	a, _, db := setupTestNuGetOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream must not be reached for blocked typosquat")
	})

	req := httptest.NewRequest(http.MethodGet, "/v3-flatcontainer/Newtonsoft.Jsom/13.0.3/Newtonsoft.Jsom.13.0.3.nupkg", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)

	artifactID := "nuget:Newtonsoft.Jsom:*"

	var name, version string
	require.NoError(t, db.QueryRow(`SELECT name, version FROM artifacts WHERE id = ?`, artifactID).Scan(&name, &version))
	assert.Equal(t, "Newtonsoft.Jsom", name)
	assert.Equal(t, "*", version, "typosquat synthetic rows always carry version=*")

	var status, reason string
	require.NoError(t, db.QueryRow(`SELECT status, COALESCE(quarantine_reason,'') FROM artifact_status WHERE artifact_id = ?`, artifactID).Scan(&status, &reason))
	assert.Equal(t, "QUARANTINED", status)
	assert.Contains(t, reason, "typosquat")

	var scannerName string
	require.NoError(t, db.QueryRow(`SELECT scanner_name FROM scan_results WHERE artifact_id = ?`, artifactID).Scan(&scannerName))
	assert.Equal(t, "builtin-typosquat", scannerName)
}

// TestNuGetAdapter_TyposquatOverride_LetsThroughWithAuditLogContainingOverrideID
// verifies that an active package-scoped override suppresses the typosquat
// pre-scan block, lets the request reach upstream, and stamps the
// EVENT_SERVED audit entry with the override_id.
func TestNuGetAdapter_TyposquatOverride_LetsThroughWithAuditLogContainingOverrideID(t *testing.T) {
	upstreamHit := false
	a, _, db := setupTestNuGetOverrideAware(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"count":0,"items":[]}`))
	})

	now := time.Now().UTC()
	res, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('nuget', 'Newtonsoft.Jsom', '', 'package', 'manual release', 'test', ?, 0)`, now)
	require.NoError(t, err)
	overrideID, err := res.LastInsertId()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Jsom/index.json", nil)
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
		"nuget:Newtonsoft.Jsom:*",
	).Scan(&metadataJSON)
	require.NoError(t, err)
	assert.Contains(t, metadataJSON, `"override_id":`)
	assert.Contains(t, metadataJSON, fmt.Sprintf(`"override_id":%d`, overrideID),
		"audit metadata must record the exact override_id that allowed the request through")
}

// TestNuGetAdapter_ScannerNotRegistered_NoBlock_PassThrough is the fail-safe:
// when no typosquat scanner is wired, nothing must block at the pre-scan stage.
func TestNuGetAdapter_ScannerNotRegistered_NoBlock_PassThrough(t *testing.T) {
	upstreamHit := false
	// setupTestNuGet wires NO scanners — PreScanTyposquat returns ok=false.
	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"count":0,"items":[]}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Jsom/index.json", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"with no typosquat scanner, pre-scan must fail open and proxy upstream")
	assert.True(t, upstreamHit)
}

// TestNuGetAdapter_LegitimatePackage_NotBlocked is the positive control:
// a real popular package (Newtonsoft.Json) must NOT be blocked by Strategy 1
// (exact-match short-circuit).
func TestNuGetAdapter_LegitimatePackage_NotBlocked(t *testing.T) {
	upstreamHit := false
	a, _ := setupTestNuGetWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"count":0,"items":[]}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Json/index.json", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"legitimate package must not be blocked by typosquat pre-scan")
	assert.True(t, upstreamHit)
}
