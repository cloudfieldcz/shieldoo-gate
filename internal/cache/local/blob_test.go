package local_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
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

func TestLocalCacheStore_StatBlob_ReturnsSize(t *testing.T) {
	store, err := local.NewLocalCacheStore(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewLocalCacheStore: %v", err)
	}
	ctx := context.Background()
	if err := store.PutBlob(ctx, "docker-push/x", []byte("hello")); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	size, err := store.StatBlob(ctx, "docker-push/x")
	if err != nil {
		t.Fatalf("StatBlob: %v", err)
	}
	if size != 5 {
		t.Fatalf("size = %d, want 5", size)
	}
	if _, err := store.StatBlob(ctx, "docker-push/missing"); err != cache.ErrBlobNotFound {
		t.Fatalf("StatBlob missing err = %v, want ErrBlobNotFound", err)
	}
}

func TestLocalCacheStore_GetBlobStream_RoundTrips(t *testing.T) {
	store, err := local.NewLocalCacheStore(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewLocalCacheStore: %v", err)
	}
	ctx := context.Background()
	_ = store.PutBlob(ctx, "docker-push/y", []byte("streamed"))
	rc, size, err := store.GetBlobStream(ctx, "docker-push/y")
	if err != nil {
		t.Fatalf("GetBlobStream: %v", err)
	}
	defer rc.Close()
	if size != 8 {
		t.Fatalf("size = %d, want 8", size)
	}
	got, _ := io.ReadAll(rc)
	if string(got) != "streamed" {
		t.Fatalf("got %q", got)
	}
	if _, _, err := store.GetBlobStream(ctx, "docker-push/missing"); err != cache.ErrBlobNotFound {
		t.Fatalf("stream missing err = %v, want ErrBlobNotFound", err)
	}
}
