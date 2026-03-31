package adapter_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// ---------------------------------------------------------------------------
// ValidatePackageName
// ---------------------------------------------------------------------------

func TestValidatePackageName_Valid(t *testing.T) {
	names := []string{"requests", "my-package", "my_package", "pkg.util", "MyPkg123"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, adapter.ValidatePackageName(name))
		})
	}
}

func TestValidatePackageName_Invalid(t *testing.T) {
	names := []string{"../etc/passwd", "pkg/../bad", "pkg;rm -rf", ""}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, adapter.ValidatePackageName(name))
		})
	}
}

// ---------------------------------------------------------------------------
// ValidateVersion
// ---------------------------------------------------------------------------

func TestValidateVersion_Valid(t *testing.T) {
	versions := []string{"1.0.0", "2.31.0", "1.0.0-beta.1", "0.1.17"}
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			assert.NoError(t, adapter.ValidateVersion(v))
		})
	}
}

func TestValidateVersion_Invalid(t *testing.T) {
	versions := []string{"../bad", "1.0;cmd", ""}
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			assert.Error(t, adapter.ValidateVersion(v))
		})
	}
}

// ---------------------------------------------------------------------------
// WriteJSONError
// ---------------------------------------------------------------------------

func TestWriteJSONError_WritesStatusAndBody(t *testing.T) {
	w := httptest.NewRecorder()
	resp := adapter.ErrorResponse{
		Error:    "blocked",
		Artifact: "pypi:requests:2.28.0",
		Reason:   "malicious package",
	}
	adapter.WriteJSONError(w, http.StatusForbidden, resp)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var got adapter.ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
	assert.Equal(t, "blocked", got.Error)
	assert.Equal(t, "malicious package", got.Reason)
}

// ---------------------------------------------------------------------------
// WriteAuditLog
// ---------------------------------------------------------------------------

func TestWriteAuditLog_InsertsRow(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	entry := model.AuditEntry{
		Timestamp:  time.Now().UTC(),
		EventType:  model.EventServed,
		ArtifactID: "pypi:requests:2.28.0",
		ClientIP:   "127.0.0.1",
		UserAgent:  "pip/23.0",
	}
	require.NoError(t, adapter.WriteAuditLog(db, entry))

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM audit_log`))
	assert.Equal(t, 1, count)
}

func TestWriteAuditLog_SetsTimestampIfZero(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	entry := model.AuditEntry{
		EventType:  model.EventBlocked,
		ArtifactID: "npm:lodash:4.17.21",
	}
	require.NoError(t, adapter.WriteAuditLog(db, entry))

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM audit_log WHERE ts IS NOT NULL`))
	assert.Equal(t, 1, count)
}

// ---------------------------------------------------------------------------
// InsertArtifact + GetArtifactStatus
// ---------------------------------------------------------------------------

func TestInsertArtifact_ThenGetStatus(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	art := model.Artifact{
		Ecosystem:      "pypi",
		Name:           "requests",
		Version:        "2.28.0",
		UpstreamURL:    "https://example.com/requests-2.28.0.tar.gz",
		SHA256:         "abc123",
		SizeBytes:      12345,
		CachedAt:       now,
		LastAccessedAt: now,
		StoragePath:    "/cache/pypi/requests/2.28.0/requests-2.28.0.tar.gz",
	}
	status := model.ArtifactStatus{
		ArtifactID: art.ID(),
		Status:     model.StatusClean,
	}

	require.NoError(t, adapter.InsertArtifact(db, art, status))

	got, err := adapter.GetArtifactStatus(db, art.ID())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, model.StatusClean, got.Status)
}

func TestGetArtifactStatus_NotFound_ReturnsNilNil(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	got, err := adapter.GetArtifactStatus(db, "pypi:nonexistent:1.0.0")
	assert.NoError(t, err)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// InsertScanResults
// ---------------------------------------------------------------------------

func TestInsertScanResults_InsertsRows(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	art := model.Artifact{
		Ecosystem:      "pypi",
		Name:           "requests",
		Version:        "2.28.0",
		UpstreamURL:    "https://example.com/requests-2.28.0.tar.gz",
		SHA256:         "abc123",
		SizeBytes:      12345,
		CachedAt:       now,
		LastAccessedAt: now,
		StoragePath:    "/cache/pypi/requests/2.28.0/requests-2.28.0.tar.gz",
	}
	status := model.ArtifactStatus{
		ArtifactID: art.ID(),
		Status:     model.StatusClean,
	}
	require.NoError(t, adapter.InsertArtifact(db, art, status))

	results := []scanner.ScanResult{
		{
			Verdict:    scanner.VerdictClean,
			Confidence: 0.95,
			ScannerID:  "trivy",
			ScannedAt:  now,
		},
	}
	require.NoError(t, adapter.InsertScanResults(db, art.ID(), results))

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM scan_results WHERE artifact_id = ?`, art.ID()))
	assert.Equal(t, 1, count)
}

func TestInsertScanResults_MultipleResults_Transactional(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	art := model.Artifact{
		Ecosystem:      "pypi",
		Name:           "flask",
		Version:        "2.3.0",
		UpstreamURL:    "https://example.com/flask-2.3.0.tar.gz",
		SHA256:         "def456",
		SizeBytes:      54321,
		CachedAt:       now,
		LastAccessedAt: now,
		StoragePath:    "/cache/pypi/flask/2.3.0/flask-2.3.0.tar.gz",
	}
	status := model.ArtifactStatus{
		ArtifactID: art.ID(),
		Status:     model.StatusClean,
	}
	require.NoError(t, adapter.InsertArtifact(db, art, status))

	results := []scanner.ScanResult{
		{
			Verdict:    scanner.VerdictClean,
			Confidence: 0.90,
			ScannerID:  "trivy",
			ScannedAt:  now,
			Duration:   2 * time.Second,
		},
		{
			Verdict:    scanner.VerdictClean,
			Confidence: 0.85,
			ScannerID:  "guarddog",
			ScannedAt:  now,
			Duration:   3 * time.Second,
			Findings:   []scanner.Finding{{Category: "test-rule", Severity: scanner.SeverityLow, Description: "test finding"}},
		},
	}
	require.NoError(t, adapter.InsertScanResults(db, art.ID(), results))

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM scan_results WHERE artifact_id = ?`, art.ID()))
	assert.Equal(t, 2, count)

	// Verify findings JSON was stored correctly for the second result.
	var findingsJSON string
	require.NoError(t, db.Get(&findingsJSON,
		`SELECT findings_json FROM scan_results WHERE artifact_id = ? AND scanner_name = 'guarddog'`, art.ID()))
	assert.Contains(t, findingsJSON, "test-rule")
}

func TestInsertScanResults_EmptySlice_NoError(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Empty results should succeed (commit an empty transaction).
	require.NoError(t, adapter.InsertScanResults(db, "pypi:foo:1.0.0", nil))
}
