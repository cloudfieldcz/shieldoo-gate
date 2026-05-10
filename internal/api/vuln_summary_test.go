package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
)

// fakeComponentService is a no-op component.Service that exists only so
// VulnEnabled() returns true. The summary handler never calls into it.
type fakeComponentService struct{ component.Service }

// TestVulnSummary_JSONShape_IsSnakeCase guards against the exact regression
// the UI hit: the anonymous aggregate struct used to ship without `json:`
// tags, so writeJSON marshalled PascalCase ("TotalCritical"). The UI types
// are snake_case ("total_critical"), so summary cards silently rendered 0
// for every metric while the underlying scan_runs already had findings.
func TestVulnSummary_JSONShape_IsSnakeCase(t *testing.T) {
	s, db := setupTestServer(t)
	s.vulnDeps = VulnDeps{Component: fakeComponentService{}}

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO projects (id, label, display_name, created_via, created_at, enabled)
		 VALUES (99, 'p99', 'p99', 'seed', ?, 1)`, now)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO components (id, project_id, name, ecosystem, ai_enabled, enabled, created_at, created_via, last_scan_id)
		 VALUES (99, 99, 'c99', 'pypi', 1, 1, ?, 'lazy', 99)`, now)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO scan_runs (id, component_id, trigger, status, started_at, finished_at,
		   critical_count, high_count, medium_count, low_count, new_critical_count, new_high_count,
		   sbom_blob_path, sbom_size_bytes, sbom_format, sbom_sha256, integrity_violated)
		 VALUES (99, 99, 'upload', 'done', ?, ?, 6, 21, 24, 0, 6, 21, 'sboms/test.json', 0, '', '', 0)`,
		now, now)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/vulnerabilities/summary", nil)
	rec := httptest.NewRecorder()
	s.handleVulnSummary(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))

	for _, k := range []string{
		"total_critical", "total_high", "total_medium", "total_low",
		"components_new_critical", "stale_components",
	} {
		_, ok := raw[k]
		assert.Truef(t, ok, "missing snake_case key %q in summary response: %s", k, rec.Body.String())
	}
	for _, k := range []string{
		"TotalCritical", "TotalHigh", "ComponentsWithNewCritical", "StaleComponents",
	} {
		_, ok := raw[k]
		assert.Falsef(t, ok, "PascalCase key %q must not appear (regression): %s", k, rec.Body.String())
	}

	assert.EqualValues(t, 6, raw["total_critical"])
	assert.EqualValues(t, 21, raw["total_high"])
	assert.EqualValues(t, 1, raw["components_new_critical"])
}
