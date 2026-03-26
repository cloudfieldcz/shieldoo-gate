package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	items := body["items"].([]any)
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
	items := body["items"].([]any)
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

	// Verify status updated
	require.NoError(t, db.QueryRow(`SELECT status FROM artifact_status WHERE artifact_id = 'pypi:evil:0.1.0'`).Scan(&status))
	assert.Equal(t, "CLEAN", status)

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
