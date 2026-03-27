package local_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface check.
var _ cache.CacheStore = (*local.LocalCacheStore)(nil)

func newTestStore(t *testing.T) (*local.LocalCacheStore, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := local.NewLocalCacheStore(dir, 10)
	require.NoError(t, err)
	return store, dir
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "artifact-")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func TestLocalCacheStore_PutGet_RoundTrip(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	src := writeTempFile(t, "hello artifact")

	artifact := scanner.Artifact{
		ID:        "pypi:requests:2.31.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.31.0",
		LocalPath: src,
	}

	err := store.Put(ctx, artifact, src)
	require.NoError(t, err)

	gotPath, err := store.Get(ctx, artifact.ID)
	require.NoError(t, err)

	data, err := os.ReadFile(gotPath)
	require.NoError(t, err)
	assert.Equal(t, "hello artifact", string(data))
}

func TestLocalCacheStore_Get_NotFound(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "pypi:nonexistent:1.0.0")
	assert.ErrorIs(t, err, cache.ErrNotFound)
}

func TestLocalCacheStore_Delete_RemovesFile(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	src := writeTempFile(t, "to be deleted")
	artifact := scanner.Artifact{
		ID:        "npm:lodash:4.17.21",
		Ecosystem: scanner.EcosystemNPM,
		Name:      "lodash",
		Version:   "4.17.21",
		LocalPath: src,
	}

	require.NoError(t, store.Put(ctx, artifact, src))

	// Verify it exists.
	_, err := store.Get(ctx, artifact.ID)
	require.NoError(t, err)

	require.NoError(t, store.Delete(ctx, artifact.ID))

	_, err = store.Get(ctx, artifact.ID)
	assert.ErrorIs(t, err, cache.ErrNotFound)
}

func TestLocalCacheStore_StoragePath_CorrectLayout(t *testing.T) {
	basePath := t.TempDir()
	store, err := local.NewLocalCacheStore(basePath, 10)
	require.NoError(t, err)

	ctx := context.Background()

	src := writeTempFile(t, "content")
	artifact := scanner.Artifact{
		ID:        "pypi:requests:2.31.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.31.0",
		LocalPath: src,
	}
	require.NoError(t, store.Put(ctx, artifact, src))

	expected := filepath.Join(basePath, "pypi", "requests", "2.31.0")
	entries, err := os.ReadDir(expected)
	require.NoError(t, err, "expected directory %s to exist", expected)
	assert.NotEmpty(t, entries, "expected at least one file in version directory")
}

func TestLocalCacheStore_PathTraversal_Rejected(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	src := writeTempFile(t, "evil")
	artifact := scanner.Artifact{
		ID:        "pypi:../evil:1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "../evil",
		Version:   "1.0.0",
		LocalPath: src,
	}

	err := store.Put(ctx, artifact, src)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestLocalCacheStore_Stats(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	stats, err := store.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.TotalItems)
	assert.Equal(t, int64(0), stats.TotalBytes)
	assert.NotNil(t, stats.ByEcosystem)
}
