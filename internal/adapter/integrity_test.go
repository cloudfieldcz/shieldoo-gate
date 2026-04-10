package adapter_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

func setupTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.DatabaseConfig{
		Backend: "",
		SQLite:  config.SQLiteConfig{Path: ":memory:"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func insertTestArtifact(t *testing.T, db *config.GateDB, id, sha string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'npm', 'test', '1.0.0', 'http://example.com', ?, 100, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '/tmp/test')`,
		id, sha)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status) VALUES (?, 'CLEAN')`, id)
	require.NoError(t, err)
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "integrity-test-*")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func sha256hex(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// --- ComputeSHA256 ---

func TestComputeSHA256_ValidFile(t *testing.T) {
	content := "hello world"
	path := writeTempFile(t, content)
	got, err := adapter.ComputeSHA256(path)
	require.NoError(t, err)
	assert.Equal(t, sha256hex(content), got)
}

func TestComputeSHA256_NonexistentFile_ReturnsError(t *testing.T) {
	_, err := adapter.ComputeSHA256("/nonexistent/path/to/file")
	assert.Error(t, err)
}

// --- VerifyCacheIntegrity ---

func TestVerifyCacheIntegrity_MatchingSHA256_ReturnsNil(t *testing.T) {
	db := setupTestDB(t)
	content := "clean artifact content"
	path := writeTempFile(t, content)
	insertTestArtifact(t, db, "npm:test:1.0.0", sha256hex(content))

	err := adapter.VerifyCacheIntegrity(db, "npm:test:1.0.0", path)
	assert.NoError(t, err)
}

func TestVerifyCacheIntegrity_MismatchSHA256_QuarantinesAndReturnsError(t *testing.T) {
	db := setupTestDB(t)
	path := writeTempFile(t, "actual file content")
	insertTestArtifact(t, db, "npm:test:1.0.0", "0000000000000000000000000000000000000000000000000000000000000000")

	err := adapter.VerifyCacheIntegrity(db, "npm:test:1.0.0", path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "INTEGRITY VIOLATION")

	// Verify artifact was quarantined.
	var status string
	require.NoError(t, db.Get(&status, `SELECT status FROM artifact_status WHERE artifact_id = ?`, "npm:test:1.0.0"))
	assert.Equal(t, string(model.StatusQuarantined), status)

	// Verify audit log was written.
	var eventType string
	require.NoError(t, db.Get(&eventType, `SELECT event_type FROM audit_log ORDER BY id DESC LIMIT 1`))
	assert.Equal(t, string(model.EventIntegrityViolation), eventType)
}

func TestVerifyCacheIntegrity_UnknownArtifact_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	path := writeTempFile(t, "content")

	err := adapter.VerifyCacheIntegrity(db, "npm:unknown:1.0.0", path)
	assert.Error(t, err) // Fail-closed: no DB record = error
}

func TestVerifyCacheIntegrity_FileNotFound_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	insertTestArtifact(t, db, "npm:test:1.0.0", "abc123")

	err := adapter.VerifyCacheIntegrity(db, "npm:test:1.0.0", "/nonexistent/file")
	assert.Error(t, err)
}

// --- VerifyUpstreamIntegrity ---

func TestVerifyUpstreamIntegrity_MatchingSHA256_ReturnsNil(t *testing.T) {
	db := setupTestDB(t)
	sha := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	insertTestArtifact(t, db, "npm:test:1.0.0", sha)

	err := adapter.VerifyUpstreamIntegrity(db, "npm:test:1.0.0", sha)
	assert.NoError(t, err)
}

func TestVerifyUpstreamIntegrity_MismatchSHA256_QuarantinesAndReturnsError(t *testing.T) {
	db := setupTestDB(t)
	insertTestArtifact(t, db, "npm:test:1.0.0", "aaaa000000000000000000000000000000000000000000000000000000000000")

	err := adapter.VerifyUpstreamIntegrity(db, "npm:test:1.0.0", "bbbb000000000000000000000000000000000000000000000000000000000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "INTEGRITY VIOLATION")
	assert.Contains(t, err.Error(), "upstream content changed")

	// Verify artifact was quarantined.
	var status string
	require.NoError(t, db.Get(&status, `SELECT status FROM artifact_status WHERE artifact_id = ?`, "npm:test:1.0.0"))
	assert.Equal(t, string(model.StatusQuarantined), status)
}

func TestVerifyUpstreamIntegrity_UnknownArtifact_ReturnsNil(t *testing.T) {
	db := setupTestDB(t)

	// No prior record — first download, should pass.
	err := adapter.VerifyUpstreamIntegrity(db, "npm:new:1.0.0", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	assert.NoError(t, err)
}
