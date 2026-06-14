package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
)

// writeLegacyBlob writes content to the legacy {root}/blobs/sha256/{ab}/{hex} path.
func writeLegacyBlob(t *testing.T, root string, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	h := hex.EncodeToString(sum[:])
	dir := filepath.Join(root, "blobs", "sha256", h[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, h), content, 0o644); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + h
}

func TestMigratePushBlobs_HappyPath_MovesAndCleans(t *testing.T) {
	legacy := t.TempDir()
	digest := writeLegacyBlob(t, legacy, []byte("layerdata"))

	backend, _ := local.NewLocalCacheStore(t.TempDir(), 0)
	dst := NewBlobStore(backend, "docker-push")

	sum, err := MigratePushBlobs(context.Background(), MigrateConfig{
		LegacyDir:   legacy,
		Dest:        dst,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("MigratePushBlobs: %v", err)
	}
	if sum.Migrated != 1 || sum.Failed != 0 {
		t.Fatalf("summary = %+v", sum)
	}
	// Present in durable backend.
	got, err := dst.Get(context.Background(), digest)
	if err != nil || string(got) != "layerdata" {
		t.Fatalf("durable get = %q, %v", got, err)
	}
	// Local copy removed: no regular files left under the legacy blobs tree.
	if _, err := os.Stat(filepath.Join(legacy, "blobs")); err == nil {
		left := 0
		_ = filepath.Walk(filepath.Join(legacy, "blobs"), func(p string, fi os.FileInfo, _ error) error {
			if fi != nil && !fi.IsDir() {
				left++
			}
			return nil
		})
		if left != 0 {
			t.Fatalf("%d local blobs left after migration", left)
		}
	}
}

func TestMigratePushBlobs_CorruptBlob_SkippedAndRetained(t *testing.T) {
	legacy := t.TempDir()
	// Write content under a WRONG digest path (poisoned/corrupt).
	wrongDir := filepath.Join(legacy, "blobs", "sha256", "de")
	_ = os.MkdirAll(wrongDir, 0o755)
	wrongPath := filepath.Join(wrongDir, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	_ = os.WriteFile(wrongPath, []byte("not-matching-the-digest"), 0o644)

	backend, _ := local.NewLocalCacheStore(t.TempDir(), 0)
	dst := NewBlobStore(backend, "docker-push")

	sum, err := MigratePushBlobs(context.Background(), MigrateConfig{LegacyDir: legacy, Dest: dst, Concurrency: 1})
	if err != nil {
		t.Fatalf("MigratePushBlobs: %v", err)
	}
	if sum.Failed != 1 || sum.Migrated != 0 {
		t.Fatalf("summary = %+v, want 1 failed", sum)
	}
	// Corrupt blob must NOT be in the durable backend.
	if _, err := dst.Get(context.Background(), "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"); err == nil {
		t.Fatal("corrupt blob must not be migrated")
	}
	// Original retained or moved aside (.corrupt) — one of them must exist.
	if _, err := os.Stat(wrongPath); err != nil {
		if _, err2 := os.Stat(wrongPath + ".corrupt"); err2 != nil {
			t.Fatal("corrupt blob neither retained nor moved-aside")
		}
	}
}

func TestMigratePushBlobs_NoLegacyDir_NoOp(t *testing.T) {
	backend, _ := local.NewLocalCacheStore(t.TempDir(), 0)
	dst := NewBlobStore(backend, "docker-push")
	sum, err := MigratePushBlobs(context.Background(), MigrateConfig{
		LegacyDir:   filepath.Join(t.TempDir(), "does-not-exist"),
		Dest:        dst,
		Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("MigratePushBlobs: %v", err)
	}
	if sum.Migrated != 0 || sum.Failed != 0 {
		t.Fatalf("summary = %+v", sum)
	}
}
