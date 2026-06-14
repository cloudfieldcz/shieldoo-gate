package local

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"
)

// TestLocalCacheStore_TwoGBBlob_RoundTrips verifies the BlobStore can store and
// retrieve a 2 GB blob (the Docker push layer cap). Skipped unless
// SHIELDOO_LARGE_BLOB_SPIKE=1 because it needs ~2 GiB RAM + ~2 GiB disk.
func TestLocalCacheStore_TwoGBBlob_RoundTrips(t *testing.T) {
	if os.Getenv("SHIELDOO_LARGE_BLOB_SPIKE") != "1" {
		t.Skip("set SHIELDOO_LARGE_BLOB_SPIKE=1 to run the 2GB spike")
	}
	const size = 2 << 30 // 2 GiB
	store, err := NewLocalCacheStore(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewLocalCacheStore: %v", err)
	}
	data := bytes.Repeat([]byte{0xAB}, size)
	want := sha256.Sum256(data)

	ctx := context.Background()
	if err := store.PutBlob(ctx, "docker-push/blobs/sha256/ab/spike", data); err != nil {
		t.Fatalf("PutBlob 2GB: %v", err)
	}
	got, err := store.GetBlob(ctx, "docker-push/blobs/sha256/ab/spike")
	if err != nil {
		t.Fatalf("GetBlob 2GB: %v", err)
	}
	if sha256.Sum256(got) != want {
		t.Fatal("2GB round-trip hash mismatch")
	}
}
