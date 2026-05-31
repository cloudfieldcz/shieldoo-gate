package api_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
)

func TestHandleGetProjectSBOM_BadID_Returns400(t *testing.T) {
	srv, _, _ := newTestServerWithProjects(t)
	srv.SetSBOMGenerator(sbom.NewGenerator(nil, "test"))
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/not-a-number/sbom", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleGetProjectSBOM_MissingProject_Returns404(t *testing.T) {
	srv, db, _ := newTestServerWithProjects(t)
	srv.SetSBOMGenerator(sbom.NewGenerator(db, "test"))
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/9999/sbom", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleGetProjectSBOM_GeneratorDisabled_Returns501(t *testing.T) {
	srv, _, svc := newTestServerWithProjects(t)
	// Deliberately do NOT call SetSBOMGenerator → handler must return 501.
	id := seedProject(t, svc, "alpha")
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+strconv.FormatInt(id, 10)+"/sbom", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)
	assert.Contains(t, rec.Body.String(), "sbom disabled")
}

func TestHandleGetProjectSBOM_HappyPath_Returns200WithHeadersAndAudit(t *testing.T) {
	srv, db, svc := newTestServerWithProjects(t)
	srv.SetSBOMGenerator(sbom.NewGenerator(db, "v1.0.0-test"))
	id := seedProject(t, svc, "marketing")
	router := srv.Routes()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+strconv.FormatInt(id, 10)+"/sbom", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// CycloneDX 1.5 MIME with version parameter.
	assert.Equal(t, "application/vnd.cyclonedx+json; version=1.5", rec.Header().Get("Content-Type"))

	// Content-Disposition triggers browser download with a date-stamped filename
	// derived from the project label.
	cd := rec.Header().Get("Content-Disposition")
	assert.True(t, strings.HasPrefix(cd, `attachment; filename="sbom-marketing-`), "unexpected Content-Disposition: %s", cd)
	assert.True(t, strings.HasSuffix(cd, `.cdx.json"`), "unexpected Content-Disposition: %s", cd)

	// Body parses as a CycloneDX 1.5 doc with empty components (no artifacts seeded).
	body := rec.Body.String()
	assert.Contains(t, body, `"bomFormat": "CycloneDX"`)
	assert.Contains(t, body, `"specVersion": "1.5"`)
	assert.Contains(t, body, `"components": []`)

	// Audit row was written with SBOM_GENERATED event type and valid JSON metadata.
	var count int
	require.NoError(t, db.Get(&count,
		`SELECT COUNT(*) FROM audit_log WHERE event_type = ? AND project_id = ?`,
		"SBOM_GENERATED", id))
	assert.Equal(t, 1, count, "expected exactly one SBOM_GENERATED audit row")

	var metaJSON string
	require.NoError(t, db.Get(&metaJSON,
		`SELECT metadata_json FROM audit_log WHERE event_type = ? AND project_id = ?`,
		"SBOM_GENERATED", id))
	assert.Contains(t, metaJSON, `"project_label":"marketing"`)
	assert.Contains(t, metaJSON, `"format":"cyclonedx-1.5-json"`)
}
