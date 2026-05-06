package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// fakeCache lets tests inject Get behavior. List/Stats/Put/Delete are unused
// by the backfill so they're left as no-ops or panic.
type fakeCache struct {
	get func(ctx context.Context, artifactID string) (string, error)
}

func (f *fakeCache) Get(ctx context.Context, id string) (string, error) {
	return f.get(ctx, id)
}
func (f *fakeCache) Put(context.Context, scanner.Artifact, string) error { return nil }
func (f *fakeCache) Delete(context.Context, string) error                { return nil }
func (f *fakeCache) List(context.Context, cache.CacheFilter) ([]string, error) {
	return nil, nil
}
func (f *fakeCache) Stats(context.Context) (cache.CacheStats, error) {
	return cache.CacheStats{}, nil
}

func newBackfillDB(t *testing.T) *config.GateDB {
	t.Helper()
	raw, err := sqlx.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	db := &config.GateDB{DB: raw}
	_, err = db.Exec(`CREATE TABLE artifacts (
        id TEXT PRIMARY KEY,
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT '',
        size_bytes INTEGER NOT NULL DEFAULT 0
    )`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE docker_manifest_meta (
        artifact_id      TEXT PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
        media_type       TEXT NOT NULL,
        is_index         INTEGER NOT NULL DEFAULT 0,
        is_attestation   INTEGER NOT NULL DEFAULT 0,
        total_size_bytes INTEGER,
        layer_count      INTEGER,
        architecture     TEXT,
        os               TEXT,
        schema_version   INTEGER NOT NULL DEFAULT 1,
        parsed_at        DATETIME NOT NULL
    )`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE data_migrations (
        name        TEXT PRIMARY KEY,
        applied_at  TIMESTAMP NOT NULL
    )`)
	require.NoError(t, err)
	return db
}

func writeManifestFile(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "manifest-*")
	require.NoError(t, err)
	_, err = f.WriteString(body)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestRunManifestMetaBackfill_BackfillsCachedRows(t *testing.T) {
	db := newBackfillDB(t)
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
		"docker:reg:img:v1", "docker", "reg/img", "v1")
	require.NoError(t, err)

	manifestPath := writeManifestFile(t, `{
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": 100},
        "layers": [{"size": 1000}, {"size": 2000}]
    }`)
	store := &fakeCache{get: func(_ context.Context, _ string) (string, error) {
		return manifestPath, nil
	}}

	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, store))

	var total *int64
	require.NoError(t, db.Get(&total, `SELECT total_size_bytes FROM docker_manifest_meta WHERE artifact_id = ?`, "docker:reg:img:v1"))
	require.NotNil(t, total)
	assert.Equal(t, int64(3100), *total)

	var marked int
	require.NoError(t, db.Get(&marked, `SELECT COUNT(*) FROM data_migrations WHERE name = ?`, manifestBackfillName))
	assert.Equal(t, 1, marked)
}

func TestRunManifestMetaBackfill_SkipsCacheMiss(t *testing.T) {
	db := newBackfillDB(t)
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
		"docker:reg:img:v1", "docker", "reg/img", "v1")
	require.NoError(t, err)

	store := &fakeCache{get: func(_ context.Context, _ string) (string, error) {
		return "", cache.ErrNotFound
	}}

	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, store))

	var rows int
	require.NoError(t, db.Get(&rows, `SELECT COUNT(*) FROM docker_manifest_meta`))
	assert.Equal(t, 0, rows, "cache miss must not insert a sidecar row")

	// Migration is still marked applied so we don't retry on every boot.
	var marked int
	require.NoError(t, db.Get(&marked, `SELECT COUNT(*) FROM data_migrations WHERE name = ?`, manifestBackfillName))
	assert.Equal(t, 1, marked)
}

func TestRunManifestMetaBackfill_SkipsAlreadyAppliedMigration(t *testing.T) {
	db := newBackfillDB(t)
	_, err := db.Exec(`INSERT INTO data_migrations (name, applied_at) VALUES (?, ?)`,
		manifestBackfillName, time.Now().UTC())
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
		"docker:reg:img:v1", "docker", "reg/img", "v1")
	require.NoError(t, err)

	called := false
	store := &fakeCache{get: func(_ context.Context, _ string) (string, error) {
		called = true
		return "", cache.ErrNotFound
	}}

	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, store))
	assert.False(t, called, "applied migration must short-circuit before touching cache")
}

func TestRunManifestMetaBackfill_OversizedManifest_Skips(t *testing.T) {
	db := newBackfillDB(t)
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
		"docker:reg:img:v1", "docker", "reg/img", "v1")
	require.NoError(t, err)

	// Write a body larger than maxBackfillManifestSize.
	bigPath := filepath.Join(t.TempDir(), "huge")
	f, err := os.Create(bigPath)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxBackfillManifestSize+1))
	require.NoError(t, f.Close())

	store := &fakeCache{get: func(_ context.Context, _ string) (string, error) {
		return bigPath, nil
	}}

	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, store))

	var rows int
	require.NoError(t, db.Get(&rows, `SELECT COUNT(*) FROM docker_manifest_meta`))
	assert.Equal(t, 0, rows, "oversized manifest must be skipped, not panic")
}

func TestRunManifestMetaBackfill_LargeBacklog_PivotsToLazy(t *testing.T) {
	if testing.Short() {
		t.Skip("inserts >50k rows; skipped in -short mode")
	}
	db := newBackfillDB(t)

	// Seed > backfillMaxBacklog rows. Use a transaction for speed.
	tx, err := db.Beginx()
	require.NoError(t, err)
	for i := 0; i < backfillMaxBacklog+5; i++ {
		_, err := tx.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
			fmt.Sprintf("docker:reg:img:v%d", i), "docker", "reg/img", fmt.Sprintf("v%d", i))
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit())

	called := false
	store := &fakeCache{get: func(_ context.Context, _ string) (string, error) {
		called = true
		return "", cache.ErrNotFound
	}}

	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, store))
	assert.False(t, called, "large backlog must short-circuit without iterating rows")

	// Migration is marked applied (pivot to lazy-on-read; we don't retry).
	var marked int
	require.NoError(t, db.Get(&marked, `SELECT COUNT(*) FROM data_migrations WHERE name = ?`, manifestBackfillName))
	assert.Equal(t, 1, marked)
}

func TestRunManifestMetaBackfill_NilStore_NoOp(t *testing.T) {
	db := newBackfillDB(t)
	// Nil store must not panic and must not mark applied (the migration didn't run).
	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, nil))

	var marked int
	require.NoError(t, db.Get(&marked, `SELECT COUNT(*) FROM data_migrations WHERE name = ?`, manifestBackfillName))
	assert.Equal(t, 0, marked, "skipped run must not be marked applied")
}

func TestRunManifestMetaBackfill_RemoteBackend_CleansTempFiles(t *testing.T) {
	db := newBackfillDB(t)
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
		"docker:reg:img:v1", "docker", "reg/img", "v1")
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
		"docker:reg:img:v2", "docker", "reg/img", "v2")
	require.NoError(t, err)

	// Simulate a remote backend: each Get returns a fresh tempfile under os.TempDir().
	var tempPaths []string
	store := &fakeCache{get: func(_ context.Context, id string) (string, error) {
		f, err := os.CreateTemp("", "shieldoo-test-cache-*")
		if err != nil {
			return "", err
		}
		_, _ = f.WriteString(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"size":1},"layers":[{"size":2}]}`)
		_ = f.Close()
		tempPaths = append(tempPaths, f.Name())
		return f.Name(), nil
	}}

	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, store))
	require.NotEmpty(t, tempPaths)

	// defer os.Remove fires when RunManifestMetaBackfill returns. Verify cleanup.
	for _, p := range tempPaths {
		_, err := os.Stat(p)
		assert.True(t, errors.Is(err, os.ErrNotExist), "tempfile %s must have been removed; err=%v", p, err)
	}
}

func TestRunManifestMetaBackfill_LocalBackend_DoesNotRemoveStablePath(t *testing.T) {
	db := newBackfillDB(t)
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version) VALUES (?, ?, ?, ?)`,
		"docker:reg:img:v1", "docker", "reg/img", "v1")
	require.NoError(t, err)

	// Stable path under t.TempDir() — NOT under os.TempDir() at the root level.
	// (t.TempDir is itself under os.TempDir, so we instead use a path the test
	// owns and that we verify is not deleted.)
	stableDir := t.TempDir()
	stablePath := filepath.Join(stableDir, "manifest")
	require.NoError(t, os.WriteFile(stablePath, []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"size":1},"layers":[{"size":2}]}`), 0o644))

	// Simulate local backend by overriding tmpDir detection: we put the file
	// outside os.TempDir(). Use an explicit non-temp path the test owns.
	// On macOS, os.TempDir() is /var/folders/... and t.TempDir() is also under it,
	// so we need to redirect via TMPDIR for the duration of the test.
	origTMPDIR := os.Getenv("TMPDIR")
	t.Cleanup(func() { _ = os.Setenv("TMPDIR", origTMPDIR) })
	require.NoError(t, os.Setenv("TMPDIR", filepath.Join(stableDir, "fake-tmp")))
	require.NoError(t, os.MkdirAll(os.Getenv("TMPDIR"), 0o755))

	store := &fakeCache{get: func(_ context.Context, _ string) (string, error) {
		return stablePath, nil
	}}

	require.NoError(t, RunManifestMetaBackfill(context.Background(), db, store))

	// stablePath was outside os.TempDir() — backfill must not remove it.
	_, err = os.Stat(stablePath)
	assert.NoError(t, err, "stable cache path must not be removed by backfill")
}

func TestValidBackfillID(t *testing.T) {
	cases := []struct {
		id    string
		valid bool
	}{
		{"docker:reg:img:v1", true},
		{"docker:reg:img", true},
		{"docker:..evil:v1", false},   // double dot inside
		{"docker:r/eg:img:v1", false}, // slash
		{"docker:reg\\img:v1", false}, // backslash
		{"docker:reg:img:v1\x00", false},
		{"docker:reg", false}, // <3 segments
	}
	for _, tc := range cases {
		assert.Equal(t, tc.valid, validBackfillID(tc.id), tc.id)
	}
}
