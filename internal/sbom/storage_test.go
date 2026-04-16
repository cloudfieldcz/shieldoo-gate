package sbom

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// failingBlobStore is a BlobStore that always fails on PutBlob.
type failingBlobStore struct{}

func (f *failingBlobStore) PutBlob(_ context.Context, _ string, _ []byte) error {
	return fmt.Errorf("simulated blob backend failure")
}
func (f *failingBlobStore) GetBlob(_ context.Context, _ string) ([]byte, error) {
	return nil, fmt.Errorf("simulated blob backend failure")
}
func (f *failingBlobStore) DeleteBlob(_ context.Context, _ string) error {
	return fmt.Errorf("simulated blob backend failure")
}

func newTestStorage(t *testing.T) (Storage, *config.GateDB, string) {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	// Seed an artifact row (FK).
	_, err = db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES ('pypi:req:2.31.0','pypi','requests','2.31.0','u','s',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp')`)
	require.NoError(t, err)

	tmpDir := filepath.Join(os.TempDir(), "shieldoo-sbom-test")
	_ = os.RemoveAll(tmpDir)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	blobs, err := local.NewLocalCacheStore(tmpDir, 1)
	require.NoError(t, err)

	return NewStorage(db, blobs, "/var/cache/shieldoo-gate"), db, tmpDir
}

func TestStorage_Write_PersistsBlobAndMetadata(t *testing.T) {
	store, _, _ := newTestStorage(t)

	meta, err := store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, []byte(sampleCycloneDX), nil)
	require.NoError(t, err)
	assert.Equal(t, "pypi:req:2.31.0", meta.ArtifactID)
	assert.Equal(t, 4, meta.ComponentCount)
	assert.Contains(t, meta.Licenses(), "Apache-2.0")
	assert.Greater(t, meta.SizeBytes, int64(0))

	// Round-trip.
	blob, format, err := store.Read(context.Background(), "pypi:req:2.31.0")
	require.NoError(t, err)
	assert.Equal(t, FormatCycloneDXJSON, format)
	assert.Contains(t, string(blob), "CycloneDX")
}

func TestStorage_Write_UpsertsMetadata(t *testing.T) {
	store, db, _ := newTestStorage(t)

	_, err := store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, []byte(sampleCycloneDX), nil)
	require.NoError(t, err)
	_, err = store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, []byte(sampleCycloneDX), nil)
	require.NoError(t, err)

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM sbom_metadata WHERE artifact_id = 'pypi:req:2.31.0'`))
	assert.Equal(t, 1, count)
}

func TestStorage_Delete(t *testing.T) {
	store, db, _ := newTestStorage(t)
	_, err := store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, []byte(sampleCycloneDX), nil)
	require.NoError(t, err)

	require.NoError(t, store.Delete(context.Background(), "pypi:req:2.31.0"))

	var count int
	require.NoError(t, db.Get(&count, `SELECT COUNT(*) FROM sbom_metadata WHERE artifact_id = 'pypi:req:2.31.0'`))
	assert.Equal(t, 0, count)

	// Idempotent.
	require.NoError(t, store.Delete(context.Background(), "pypi:req:2.31.0"))
}

func TestStorage_GetMetadata_NotFound(t *testing.T) {
	store, _, _ := newTestStorage(t)
	_, err := store.GetMetadata(context.Background(), "missing")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestStorage_Write_SanitizesCachePaths(t *testing.T) {
	store, _, _ := newTestStorage(t)
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"x","properties":[{"name":"Path","value":"/var/cache/shieldoo-gate/pypi/x.whl"}]}]}`)
	_, err := store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, raw, nil)
	require.NoError(t, err)
	blob, _, err := store.Read(context.Background(), "pypi:req:2.31.0")
	require.NoError(t, err)
	assert.NotContains(t, string(blob), "/var/cache/shieldoo-gate")
}

func TestStorage_Write_BlobFailure_PersistsMetadata(t *testing.T) {
	// Use a blob store that always fails — metadata should still be written.
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES ('pypi:req:2.31.0','pypi','requests','2.31.0','u','s',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp')`)
	require.NoError(t, err)

	store := NewStorage(db, &failingBlobStore{}, "/var/cache/shieldoo-gate")

	meta, err := store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, []byte(sampleCycloneDX), nil)
	require.NoError(t, err, "Write must succeed even when blob backend fails")

	// Metadata should be persisted with licenses extracted.
	assert.Equal(t, "pypi:req:2.31.0", meta.ArtifactID)
	assert.Contains(t, meta.Licenses(), "Apache-2.0")
	assert.Equal(t, "", meta.BlobPath, "BlobPath should be empty when blob write failed")

	// GetMetadata should find the row.
	dbMeta, err := store.GetMetadata(context.Background(), "pypi:req:2.31.0")
	require.NoError(t, err)
	assert.Contains(t, dbMeta.Licenses(), "Apache-2.0")
	assert.Equal(t, "", dbMeta.BlobPath)

	// Read (blob) should fail gracefully.
	_, _, err = store.Read(context.Background(), "pypi:req:2.31.0")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blob unavailable")

	// Delete should succeed (no blob to remove).
	require.NoError(t, store.Delete(context.Background(), "pypi:req:2.31.0"))
}

func TestStorage_Write_MergesScannerLicenses(t *testing.T) {
	// When the CycloneDX blob has 0 components but the scanner's license
	// extractor found licenses, they should appear in the metadata.
	store, _, _ := newTestStorage(t)
	emptyBOM := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)

	meta, err := store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, emptyBOM, []string{"MIT", "Apache-2.0"})
	require.NoError(t, err)
	assert.Equal(t, 0, meta.ComponentCount)
	assert.Contains(t, meta.Licenses(), "MIT")
	assert.Contains(t, meta.Licenses(), "Apache-2.0")

	// Verify from DB.
	dbMeta, err := store.GetMetadata(context.Background(), "pypi:req:2.31.0")
	require.NoError(t, err)
	assert.Contains(t, dbMeta.Licenses(), "MIT")
	assert.Contains(t, dbMeta.Licenses(), "Apache-2.0")
}

func TestStorage_Write_ScannerLicensesDedup(t *testing.T) {
	// Scanner licenses that already exist in the CycloneDX parse result
	// should not be duplicated.
	store, _, _ := newTestStorage(t)

	meta, err := store.Write(context.Background(), "pypi:req:2.31.0", FormatCycloneDXJSON, []byte(sampleCycloneDX), []string{"Apache-2.0", "MIT"})
	require.NoError(t, err)
	// Apache-2.0 is in the sample CycloneDX and in scannerLicenses — should appear once.
	count := 0
	for _, l := range meta.Licenses() {
		if l == "Apache-2.0" {
			count++
		}
	}
	assert.Equal(t, 1, count, "Apache-2.0 should not be duplicated")
	assert.Contains(t, meta.Licenses(), "MIT", "extra scanner license should be added")
}
