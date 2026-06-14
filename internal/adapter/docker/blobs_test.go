package docker

import (
	"context"
	"io"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
)

func newTestBlobStore(t *testing.T) *BlobStore {
	t.Helper()
	backend, err := local.NewLocalCacheStore(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	return NewBlobStore(backend, "docker-push")
}

func TestBlobStore_PutGet_RoundTrips(t *testing.T) {
	bs := newTestBlobStore(t)
	ctx := context.Background()
	digest := "sha256:abcd1234"
	if err := bs.Put(ctx, digest, []byte("layer")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := bs.Get(ctx, digest)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "layer" {
		t.Fatalf("got %q", got)
	}
}

func TestBlobStore_GetStream_RoundTrips(t *testing.T) {
	bs := newTestBlobStore(t)
	ctx := context.Background()
	_ = bs.Put(ctx, "sha256:dead", []byte("streamed-layer"))
	rc, size, err := bs.GetStream(ctx, "sha256:dead")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	defer rc.Close()
	if size != int64(len("streamed-layer")) {
		t.Fatalf("size = %d", size)
	}
	data, _ := io.ReadAll(rc)
	if string(data) != "streamed-layer" {
		t.Fatalf("got %q", data)
	}
}

func TestBlobStore_ExistsAndStat(t *testing.T) {
	bs := newTestBlobStore(t)
	ctx := context.Background()
	_ = bs.Put(ctx, "sha256:beef", []byte("xyz"))
	ok, err := bs.Exists(ctx, "sha256:beef")
	if err != nil || !ok {
		t.Fatalf("Exists = %v, %v", ok, err)
	}
	ok, _ = bs.Exists(ctx, "sha256:0000")
	if ok {
		t.Fatal("Exists should be false for missing")
	}
	size, err := bs.Stat(ctx, "sha256:beef")
	if err != nil || size != 3 {
		t.Fatalf("Stat = %d, %v", size, err)
	}
}

func TestBlobStore_DigestKey_RejectsTraversal(t *testing.T) {
	bs := newTestBlobStore(t)
	for _, bad := range []string{"", "noColon", "sha256:../escape", "sha256:a/b", "sha256:"} {
		if _, err := bs.digestKey(bad); err == nil {
			t.Errorf("digestKey(%q) should error", bad)
		}
	}
	key, err := bs.digestKey("sha256:abcdef")
	if err != nil {
		t.Fatalf("valid digest: %v", err)
	}
	if key != "docker-push/blobs/sha256/ab/abcdef" {
		t.Fatalf("key = %q", key)
	}
}
