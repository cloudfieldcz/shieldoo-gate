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
