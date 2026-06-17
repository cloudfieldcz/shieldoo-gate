package tmpjanitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// staleMtime is comfortably older than any maxAge used in these tests.
var (
	now     = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	staleAt = now.Add(-2 * time.Hour)
	freshAt = now.Add(-1 * time.Minute)
	testAge = 1 * time.Hour
)

func mkStaleFile(t *testing.T, dir, name string, mtime time.Time) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("scratch"), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	return p
}

func mkStaleDir(t *testing.T, dir, name string, mtime time.Time) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(p, "inner"), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(p, "inner", "f"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write inner: %v", err)
	}
	if err := os.Chtimes(p, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	return p
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func newJanitor(dir string, denylist ...string) *Janitor {
	return New(Config{Dir: dir, MaxAge: testAge, Denylist: denylist})
}

func TestSweep_StaleRemoved_FreshKept_ReturnsClean(t *testing.T) {
	dir := t.TempDir()
	stale := mkStaleFile(t, dir, "shieldoo-gate-pypi-abc.tmp", staleAt)
	fresh := mkStaleFile(t, dir, "shieldoo-gate-npm-xyz.tmp", freshAt)
	trivy := mkStaleDir(t, dir, "shieldoo-trivy-scratch-1", staleAt)

	n := newJanitor(dir).Sweep(now)

	if n != 2 {
		t.Fatalf("expected 2 deleted, got %d", n)
	}
	if exists(stale) {
		t.Error("stale staging file should be removed")
	}
	if exists(trivy) {
		t.Error("stale trivy scratch dir should be removed")
	}
	if !exists(fresh) {
		t.Error("fresh staging file must be kept (could be an in-flight scan)")
	}
}

func TestSweep_DenylistProtectsSamePrefixDecoy_BlobStoreSurvives(t *testing.T) {
	dir := t.TempDir()
	// The push blob store is a directory; a decoy file with the same name is
	// planted next to it. Both the files-only guard and the denylist apply.
	blobDir := mkStaleDir(t, dir, "shieldoo-gate-blobs", staleAt)
	decoyFile := mkStaleFile(t, dir, "shieldoo-gate-blobs-decoy", staleAt)
	socketDecoy := mkStaleFile(t, dir, "shieldoo-bridge.sock", staleAt)

	j := newJanitor(dir, "shieldoo-gate-blobs", "shieldoo-gate-blobs-decoy", "shieldoo-bridge.sock")
	j.Sweep(now)

	if !exists(blobDir) {
		t.Error("blob store directory must never be removed")
	}
	if !exists(decoyFile) {
		t.Error("denylisted same-prefix decoy must survive")
	}
	if !exists(socketDecoy) {
		t.Error("denylisted socket basename must survive")
	}
}

func TestSweep_GateDirectoryNeverDeleted_FilesOnlyGuard(t *testing.T) {
	dir := t.TempDir()
	// A stale directory under the files-only shieldoo-gate- prefix, NOT on the
	// denylist — the structural files-only guard alone must protect it.
	gateDir := mkStaleDir(t, dir, "shieldoo-gate-blobs", staleAt)

	n := newJanitor(dir).Sweep(now)

	if n != 0 {
		t.Fatalf("expected 0 deleted, got %d", n)
	}
	if !exists(gateDir) {
		t.Error("a directory under shieldoo-gate- must never be deleted even without denylist")
	}
}

func TestSweep_SymlinkSkipped(t *testing.T) {
	dir := t.TempDir()
	// A real protected target plus a matching-prefix symlink pointing at it.
	target := mkStaleFile(t, dir, "real-socket", staleAt)
	link := filepath.Join(dir, "shieldoo-gate-link.tmp")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.Chtimes(link, staleAt, staleAt); err != nil {
		t.Fatalf("chtimes link: %v", err)
	}

	n := newJanitor(dir).Sweep(now)

	if n != 0 {
		t.Fatalf("expected 0 deleted, got %d", n)
	}
	if !exists(link) {
		t.Error("symlink must never be deleted")
	}
	if !exists(target) {
		t.Error("symlink target must never be followed/deleted")
	}
}

func TestSweep_DotDotNameRejected(t *testing.T) {
	dir := t.TempDir()
	evil := mkStaleFile(t, dir, "shieldoo-trivy-..evil", staleAt)

	n := newJanitor(dir).Sweep(now)

	if n != 0 {
		t.Fatalf("expected 0 deleted, got %d", n)
	}
	if !exists(evil) {
		t.Error("entry whose name contains .. must be rejected (skipped), not deleted")
	}
}

func TestSweep_NonMatchingPrefixKept(t *testing.T) {
	dir := t.TempDir()
	// The sandbox's own temp uses sgw-sandbox-*, handled by its own worker.
	sandbox := mkStaleDir(t, dir, "sgw-sandbox-123", staleAt)
	random := mkStaleFile(t, dir, "some-other-file", staleAt)

	n := newJanitor(dir).Sweep(now)

	if n != 0 {
		t.Fatalf("expected 0 deleted, got %d", n)
	}
	if !exists(sandbox) {
		t.Error("sgw-sandbox-* is out of scope (sandbox owns it)")
	}
	if !exists(random) {
		t.Error("unrelated files must never be touched")
	}
}

func TestSweep_PerEntryDeleteFailureDoesNotAbortSweep(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := t.TempDir()
	// An undeletable dir (0000, with content) followed by a deletable file.
	stuck := mkStaleDir(t, dir, "shieldoo-trivy-stuck", staleAt)
	if err := os.Chmod(stuck, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(stuck, 0o755) }) // let t.TempDir clean up
	ok := mkStaleFile(t, dir, "shieldoo-gate-pypi-ok.tmp", staleAt)

	n := newJanitor(dir).Sweep(now)

	if n != 1 {
		t.Fatalf("expected 1 deleted (sweep must continue past the failure), got %d", n)
	}
	if !exists(stuck) {
		t.Error("undeletable entry should remain (delete failed, but skipped not aborted)")
	}
	if exists(ok) {
		t.Error("deletable entry after a failure must still be removed")
	}
}

func TestSweep_PerSweepCapDeletesOldestFirst(t *testing.T) {
	dir := t.TempDir()
	// Five stale files with strictly increasing mtimes; cap at 2.
	names := []string{
		"shieldoo-gate-a.tmp", // oldest
		"shieldoo-gate-b.tmp",
		"shieldoo-gate-c.tmp",
		"shieldoo-gate-d.tmp",
		"shieldoo-gate-e.tmp", // newest (but still stale)
	}
	for i, n := range names {
		mkStaleFile(t, dir, n, now.Add(-time.Duration(5-i)*time.Hour))
	}

	j := New(Config{Dir: dir, MaxAge: testAge, MaxDelete: 2})
	deleted := j.Sweep(now)

	if deleted != 2 {
		t.Fatalf("cap should limit to 2 deletions, got %d", deleted)
	}
	// The two oldest (a, b) must be gone; the rest survive.
	if exists(filepath.Join(dir, "shieldoo-gate-a.tmp")) {
		t.Error("oldest entry should be deleted first")
	}
	if exists(filepath.Join(dir, "shieldoo-gate-b.tmp")) {
		t.Error("second-oldest entry should be deleted")
	}
	for _, n := range []string{"shieldoo-gate-c.tmp", "shieldoo-gate-d.tmp", "shieldoo-gate-e.tmp"} {
		if !exists(filepath.Join(dir, n)) {
			t.Errorf("newer entry %s should survive the cap and drain next cycle", n)
		}
	}
}

func TestSweep_SbomTempFilesRemoved(t *testing.T) {
	dir := t.TempDir()
	sbom := mkStaleFile(t, dir, "shieldoo-sbom-123.json", staleAt)
	// A directory under the sbom prefix must NOT be removed (files-only rule).
	sbomDir := mkStaleDir(t, dir, "shieldoo-sbom-dir", staleAt)

	newJanitor(dir).Sweep(now)

	if exists(sbom) {
		t.Error("stale sbom temp file should be removed")
	}
	if !exists(sbomDir) {
		t.Error("a directory under shieldoo-sbom- is files-only and must survive")
	}
}

func TestSweep_CloudCacheTempFilesRemoved(t *testing.T) {
	dir := t.TempDir()
	// Download-to-temp scratch left by the cloud cache backends (issue #24).
	// Each is always a regular file (os.CreateTemp); files-only.
	azblob := mkStaleFile(t, dir, "shieldoo-azblob-cache-123456", staleAt)
	s3 := mkStaleFile(t, dir, "shieldoo-s3-cache-abcdef", staleAt)
	gcs := mkStaleFile(t, dir, "shieldoo-gcs-cache-789xyz", staleAt)
	// A fresh azblob temp could be a download still being served/scanned.
	freshAz := mkStaleFile(t, dir, "shieldoo-azblob-cache-inflight", freshAt)
	// A directory under a cloud-cache prefix must NOT be removed (files-only).
	azDir := mkStaleDir(t, dir, "shieldoo-azblob-cache-dir", staleAt)

	n := newJanitor(dir).Sweep(now)

	if n != 3 {
		t.Fatalf("expected 3 deleted, got %d", n)
	}
	for _, p := range []string{azblob, s3, gcs} {
		if exists(p) {
			t.Errorf("stale cloud-cache temp %s should be removed", filepath.Base(p))
		}
	}
	if !exists(freshAz) {
		t.Error("fresh cloud-cache temp must be kept (could be an in-flight download)")
	}
	if !exists(azDir) {
		t.Error("a directory under a cloud-cache prefix is files-only and must survive")
	}
}

func TestSweep_SemgrepScratchRemoved_FilesAndDirs(t *testing.T) {
	dir := t.TempDir()
	// semgrep (invoked by GuardDog in the scanner-bridge) writes both files and
	// dirs to the shared /tmp; only our scan runs semgrep, so owning the prefix
	// is safe (issue #24).
	semFile := mkStaleFile(t, dir, "semgrep-output-123", staleAt)
	semDir := mkStaleDir(t, dir, "semgrep-core-456", staleAt)
	semFresh := mkStaleFile(t, dir, "semgrep-inflight", freshAt)

	n := newJanitor(dir).Sweep(now)

	if n != 2 {
		t.Fatalf("expected 2 deleted, got %d", n)
	}
	if exists(semFile) {
		t.Error("stale semgrep file should be removed")
	}
	if exists(semDir) {
		t.Error("stale semgrep dir should be removed (semgrep makes both files and dirs)")
	}
	if !exists(semFresh) {
		t.Error("fresh semgrep scratch must be kept (could be an in-flight scan)")
	}
}

func TestMatchRule(t *testing.T) {
	j := New(Config{Dir: "/x", MaxAge: testAge})
	cases := []struct {
		name  string
		isDir bool
		want  bool
	}{
		{"shieldoo-trivy-scratch-1", true, true},
		{"shieldoo-trivy-file", false, true},
		{"shieldoo-sbom-x.json", false, true},
		{"shieldoo-sbom-dir", true, false}, // files only
		{"shieldoo-gate-pypi.tmp", false, true},
		{"shieldoo-gate-blobs", true, false}, // files only -> blob store excluded
		{"shieldoo-azblob-cache-1", false, true},
		{"shieldoo-azblob-cache-1", true, false}, // files only
		{"shieldoo-s3-cache-1", false, true},
		{"shieldoo-s3-cache-1", true, false}, // files only
		{"shieldoo-gcs-cache-1", false, true},
		{"shieldoo-gcs-cache-1", true, false}, // files only
		{"semgrep-output", false, true},
		{"semgrep-core", true, true}, // semgrep makes both files and dirs
		{"sgw-sandbox-1", true, false},
		{"unrelated", false, false},
	}
	for _, c := range cases {
		if _, ok := j.matchRule(c.name, c.isDir); ok != c.want {
			t.Errorf("matchRule(%q, dir=%v) = %v, want %v", c.name, c.isDir, ok, c.want)
		}
	}
}

func TestRun_InitialSweepThenStopsOnCtxCancel(t *testing.T) {
	dir := t.TempDir()
	stale := mkStaleFile(t, dir, "shieldoo-gate-x.tmp", time.Now().Add(-2*time.Hour))

	j := New(Config{Dir: dir, MaxAge: testAge, Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() { j.Run(ctx); close(done) }()

	// The initial sweep runs before the first ticker tick; poll for its effect.
	deadline := time.Now().Add(2 * time.Second)
	for exists(stale) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exists(stale) {
		t.Error("Run should perform an initial sweep before the first interval")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}
