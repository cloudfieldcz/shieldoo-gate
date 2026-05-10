package local_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListBlobs_RoundTripsPutGet verifies ListBlobs returns the same relative
// paths PutBlob accepted, that nested directories are walked, and that in-flight
// temp files are filtered out.
func TestListBlobs_RoundTripsPutGet(t *testing.T) {
	dir := t.TempDir()
	store, err := local.NewLocalCacheStore(dir, 10)
	require.NoError(t, err)
	ctx := context.Background()

	want := []string{
		"sboms/components/1/2025/run-1.json",
		"sboms/components/1/2025/run-2.json",
		"sboms/components/2/2025/run-3.json",
	}
	for _, p := range want {
		require.NoError(t, store.PutBlob(ctx, p, []byte("payload")))
	}

	// Drop a stray temp file alongside one of the blobs to confirm it's filtered.
	stray := filepath.Join(dir, "sboms/components/1/2025/.blob-tmp-stray")
	require.NoError(t, os.WriteFile(stray, []byte("x"), 0o644))

	got, err := store.ListBlobs(ctx, "sboms/components/")
	require.NoError(t, err)
	sort.Strings(got)
	sort.Strings(want)
	assert.Equal(t, want, got)
}

// TestListBlobs_MissingPrefixReturnsNil ensures a missing prefix is not an error
// — the orphan sweeper relies on this to no-op cleanly on a fresh install.
func TestListBlobs_MissingPrefixReturnsNil(t *testing.T) {
	dir := t.TempDir()
	store, err := local.NewLocalCacheStore(dir, 10)
	require.NoError(t, err)

	got, err := store.ListBlobs(context.Background(), "sboms/components/")
	require.NoError(t, err)
	assert.Nil(t, got)
}

// TestListBlobs_RejectsTraversal exercises the sanitize-path guard the rest of
// the BlobStore methods share.
func TestListBlobs_RejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	store, err := local.NewLocalCacheStore(dir, 10)
	require.NoError(t, err)

	_, err = store.ListBlobs(context.Background(), "../etc")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "traversal"))
}
