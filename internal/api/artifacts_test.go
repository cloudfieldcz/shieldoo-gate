package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleListArtifacts_Empty_ReturnsEmptyPage(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(0), body["total"])
	assert.Equal(t, float64(1), body["page"])
	assert.Equal(t, float64(50), body["per_page"])
	items := body["data"].([]any)
	assert.Empty(t, items)
}

func TestHandleListArtifacts_WithData_ReturnsList(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0", "pypi", "requests", "2.31.0")
	insertTestArtifact(t, db, "pypi:flask:2.0.0", "pypi", "flask", "2.0.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?page=1&per_page=10", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(2), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 2)
}

func TestHandleGetArtifact_NotFound_Returns404(t *testing.T) {
	srv, _ := newTestServer(t)
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/pypi:nonexistent:1.0.0", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleGetArtifact_Exists_ReturnsArtifact(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0", "pypi", "requests", "2.31.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/pypi:requests:2.31.0", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "pypi", body["ecosystem"])
	assert.Equal(t, "requests", body["name"])
	assert.Equal(t, "2.31.0", body["version"])
}

func TestHandleQuarantineAndRelease_Flow(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:evil:0.1.0", "pypi", "evil", "0.1.0")

	router := srv.Routes()

	// Quarantine
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/pypi:evil:0.1.0/quarantine", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	var qBody map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&qBody))
	assert.Equal(t, "QUARANTINED", qBody["status"])

	// Verify status in DB
	var status string
	require.NoError(t, db.QueryRow(`SELECT status FROM artifact_status WHERE artifact_id = 'pypi:evil:0.1.0'`).Scan(&status))
	assert.Equal(t, "QUARANTINED", status)

	// Verify audit log
	var auditCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'QUARANTINED' AND artifact_id = 'pypi:evil:0.1.0'`).Scan(&auditCount))
	assert.Equal(t, 1, auditCount)

	// Release
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/pypi:evil:0.1.0/release", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)

	var rBody map[string]any
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&rBody))
	assert.Equal(t, "CLEAN", rBody["status"])

	// Verify status updated and quarantine fields cleared
	require.NoError(t, db.QueryRow(`SELECT status FROM artifact_status WHERE artifact_id = 'pypi:evil:0.1.0'`).Scan(&status))
	assert.Equal(t, "CLEAN", status)

	var quarantineReason string
	require.NoError(t, db.QueryRow(`SELECT COALESCE(quarantine_reason, '') FROM artifact_status WHERE artifact_id = 'pypi:evil:0.1.0'`).Scan(&quarantineReason))
	assert.Empty(t, quarantineReason, "quarantine_reason should be cleared after release")

	var rescanDueAt *string
	require.NoError(t, db.QueryRow(`SELECT rescan_due_at FROM artifact_status WHERE artifact_id = 'pypi:evil:0.1.0'`).Scan(&rescanDueAt))
	assert.Nil(t, rescanDueAt, "rescan_due_at should be NULL after release to prevent immediate re-quarantine")

	// Verify release audit log entry
	var releaseCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'RELEASED' AND artifact_id = 'pypi:evil:0.1.0'`).Scan(&releaseCount))
	assert.Equal(t, 1, releaseCount)

	// Verify policy override was created
	var overrideCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM policy_overrides WHERE ecosystem = 'pypi' AND name = 'evil' AND version = '0.1.0' AND revoked = FALSE`).Scan(&overrideCount))
	assert.Equal(t, 1, overrideCount, "release should create a policy override")

	// Release again — should reuse existing override, not create a duplicate
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/pypi:evil:0.1.0/release", nil)
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code)

	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM policy_overrides WHERE ecosystem = 'pypi' AND name = 'evil' AND version = '0.1.0' AND revoked = FALSE`).Scan(&overrideCount))
	assert.Equal(t, 1, overrideCount, "second release should reuse existing override, not create duplicate")
}

func TestHandleRelease_ScopedNpmPackage_OverrideUsesOriginalName(t *testing.T) {
	srv, db := newTestServer(t)

	// Insert artifact with scoped npm name — ID uses underscores, name uses original format.
	insertTestArtifact(t, db, "npm:remix-run_router:1.16.1", "npm", "@remix-run/router", "1.16.1")

	router := srv.Routes()

	// Quarantine first
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/npm:remix-run_router:1.16.1/quarantine", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Release — this should create override with original name "@remix-run/router"
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/npm:remix-run_router:1.16.1/release", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)

	// Verify override uses the original name, NOT the sanitized ID name
	var overrideName string
	err := db.QueryRow(
		`SELECT name FROM policy_overrides WHERE ecosystem = 'npm' AND version = '1.16.1' AND revoked = FALSE`,
	).Scan(&overrideName)
	require.NoError(t, err)
	assert.Equal(t, "@remix-run/router", overrideName,
		"policy override must use original package name, not sanitized ID name")
}

func TestHandleRelease_TyposquatPlaceholder_CreatesPackageScopeOverride(t *testing.T) {
	srv, db := newTestServer(t)

	// Synthetic typosquat-block artifact: version="*" indicates a name-only block.
	insertTestArtifact(t, db, "npm:lodsah:*", "npm", "lodsah", "*")

	// Quarantine to mirror the real pre-scan state.
	router := srv.Routes()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/npm:lodsah:*/quarantine", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Release: must create a PACKAGE-scoped override with empty version.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/npm:lodsah:*/release", nil)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)

	var scope, version string
	err := db.QueryRow(
		`SELECT scope, version FROM policy_overrides
		 WHERE ecosystem = 'npm' AND name = 'lodsah' AND revoked = FALSE`,
	).Scan(&scope, &version)
	require.NoError(t, err)
	assert.Equal(t, "package", scope, "typosquat placeholder release must create package-scoped override")
	assert.Equal(t, "", version, "package-scoped override must have empty version")

	// Status should be CLEAN.
	var status string
	require.NoError(t, db.QueryRow(`SELECT status FROM artifact_status WHERE artifact_id = 'npm:lodsah:*'`).Scan(&status))
	assert.Equal(t, "CLEAN", status)
}

func TestHandleRescanArtifact_Exists_Returns202(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "npm:lodash:4.17.21", "npm", "lodash", "4.17.21")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/npm:lodash:4.17.21/rescan", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
}

func TestHandleGetArtifactScanResults_NoResults_ReturnsEmptyArray(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "npm:lodash:4.17.21", "npm", "lodash", "4.17.21")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/npm:lodash:4.17.21/scan-results", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body []any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Empty(t, body)
}

func TestHandleListArtifacts_FilterByEcosystem_ReturnsFiltered(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0", "pypi", "requests", "2.31.0")
	insertTestArtifact(t, db, "pypi:flask:2.0.0", "pypi", "flask", "2.0.0")
	insertTestArtifact(t, db, "npm:lodash:4.17.21", "npm", "lodash", "4.17.21")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?ecosystem=pypi", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(2), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 2)
	for _, item := range items {
		assert.Equal(t, "pypi", item.(map[string]any)["ecosystem"])
	}
}

func TestHandleListArtifacts_FilterByStatus_ReturnsFiltered(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:evil:0.1.0", "pypi", "evil", "0.1.0")
	insertTestArtifact(t, db, "pypi:good:1.0.0", "pypi", "good", "1.0.0")

	_, err := db.Exec(`INSERT INTO artifact_status (artifact_id, status) VALUES ('pypi:evil:0.1.0', 'QUARANTINED')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO artifact_status (artifact_id, status) VALUES ('pypi:good:1.0.0', 'CLEAN')`)
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?status=QUARANTINED", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(1), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 1)
	first := items[0].(map[string]any)["status"].(map[string]any)
	assert.Equal(t, "QUARANTINED", first["status"])
}

func TestHandleListArtifacts_FilterByPendingScan_ReturnsArtifactsWithoutStatus(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:new:1.0.0", "pypi", "new", "1.0.0")
	insertTestArtifact(t, db, "pypi:scanned:2.0.0", "pypi", "scanned", "2.0.0")

	_, err := db.Exec(`INSERT INTO artifact_status (artifact_id, status) VALUES ('pypi:scanned:2.0.0', 'CLEAN')`)
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?status=PENDING_SCAN", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(1), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 1)
	assert.Equal(t, "new", items[0].(map[string]any)["name"])
}

func TestHandleListArtifacts_SearchByName_ReturnsMatching(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0", "pypi", "requests", "2.31.0")
	insertTestArtifact(t, db, "pypi:flask:2.0.0", "pypi", "flask", "2.0.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?name=req", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(1), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 1)
	assert.Equal(t, "requests", items[0].(map[string]any)["name"])
}

func TestHandleListArtifacts_SearchByVersion_ReturnsMatching(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0", "pypi", "requests", "2.31.0")
	insertTestArtifact(t, db, "pypi:flask:2.0.0", "pypi", "flask", "2.0.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?version=2.31", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(1), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 1)
	assert.Equal(t, "requests", items[0].(map[string]any)["name"])
}

func TestHandleListArtifacts_CombinedFilters_ReturnsIntersection(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0", "pypi", "requests", "2.31.0")
	insertTestArtifact(t, db, "pypi:flask:2.0.0", "pypi", "flask", "2.0.0")
	insertTestArtifact(t, db, "npm:request:1.0.0", "npm", "request", "1.0.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?ecosystem=pypi&name=req", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(1), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 1)
	assert.Equal(t, "requests", items[0].(map[string]any)["name"])
}

func TestHandleListArtifacts_NoMatch_ReturnsEmpty(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0", "pypi", "requests", "2.31.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?name=nonexistent", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(0), body["total"])
	items := body["data"].([]any)
	assert.Empty(t, items)
}

func TestHandleListArtifacts_SearchNameWithWildcard_EscapedCorrectly(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:test%pkg:1.0.0", "pypi", "test%pkg", "1.0.0")
	insertTestArtifact(t, db, "pypi:testXpkg:1.0.0", "pypi", "testXpkg", "1.0.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?name=test%25pkg", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(1), body["total"])
	items := body["data"].([]any)
	assert.Len(t, items, 1)
	assert.Equal(t, "test%pkg", items[0].(map[string]any)["name"])
}

func TestHandleListArtifacts_NameTooLong_Returns400(t *testing.T) {
	srv, _ := newTestServer(t)

	router := srv.Routes()
	longName := strings.Repeat("a", 257)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts?name="+longName, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleGetArtifact_FourSegmentID_ReturnsRawDBID(t *testing.T) {
	srv, db := newTestServer(t)

	// Simulate a PyPI artifact with a 4-segment DB id (ecosystem:name:version:filename).
	insertTestArtifact(t, db, "pypi:requests:2.31.0:requests-2.31.0-py3-none-any.whl", "pypi", "requests", "2.31.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/pypi:requests:2.31.0:requests-2.31.0-py3-none-any.whl", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "pypi:requests:2.31.0:requests-2.31.0-py3-none-any.whl", body["id"],
		"API response id must match the raw DB id, not a 3-segment computed ID")
}

func TestHandleListArtifacts_FourSegmentID_ReturnsRawDBID(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:requests:2.31.0:requests-2.31.0-py3-none-any.whl", "pypi", "requests", "2.31.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	items := body["data"].([]any)
	require.Len(t, items, 1)
	assert.Equal(t, "pypi:requests:2.31.0:requests-2.31.0-py3-none-any.whl", items[0].(map[string]any)["id"],
		"list API response id must match the raw DB id, not a 3-segment computed ID")
}

func TestHandleListArtifacts_OrderByName_ReturnsAlphabetical(t *testing.T) {
	srv, db := newTestServer(t)

	insertTestArtifact(t, db, "pypi:zlib:1.0.0", "pypi", "zlib", "1.0.0")
	insertTestArtifact(t, db, "pypi:aiohttp:3.0.0", "pypi", "aiohttp", "3.0.0")
	insertTestArtifact(t, db, "pypi:flask:2.0.0", "pypi", "flask", "2.0.0")

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	items := body["data"].([]any)
	require.Len(t, items, 3)
	assert.Equal(t, "aiohttp", items[0].(map[string]any)["name"])
	assert.Equal(t, "flask", items[1].(map[string]any)["name"])
	assert.Equal(t, "zlib", items[2].(map[string]any)["name"])
}
