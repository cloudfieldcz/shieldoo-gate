package tmpjanitor

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSweep_ProductionWiring_SocketAndBlobStoreSurvive constructs the janitor
// exactly as cmd/shieldoo-gate/main.go does (DefaultRules, the production
// denylist of the gRPC socket basename + the legacy push blob-store dir) and
// asserts the Phase 5 invariants the containerized harness cannot exercise
// (it can neither exec/restart the gate nor trigger an on-demand sweep):
//
//   - a stale shieldoo-trivy-* scratch dir is reclaimed;
//   - a fresh in-flight staging file survives;
//   - the live gRPC unix socket survives;
//   - the legacy /tmp push blob-store directory (ADR-009, pending migration)
//     survives via both the files-only guard and the denylist.
func TestSweep_ProductionWiring_SocketAndBlobStoreSurvive(t *testing.T) {
	// A short base dir: macOS caps unix socket paths at ~104 chars, and
	// t.TempDir() under /var/folders is already too long.
	dir, err := os.MkdirTemp("/tmp", "tj")
	if err != nil {
		dir = t.TempDir()
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}

	// A real unix-domain socket, as the bridge creates at BRIDGE_SOCKET.
	socketName := "shieldoo-bridge.sock"
	socketPath := filepath.Join(dir, socketName)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix socket unsupported here: %v", err)
	}
	defer ln.Close()
	old := time.Now().Add(-3 * time.Hour)
	_ = os.Chtimes(socketPath, old, old) // backdate so age alone would not protect it

	// Stale Trivy scratch (must be reclaimed) and a fresh staging file (in-flight).
	staleTrivy := mkStaleDir(t, dir, "shieldoo-trivy-scratch-deadbeef", old)
	freshStaging := mkStaleFile(t, dir, "shieldoo-gate-pypi-live.tmp", time.Now())

	// Legacy /tmp push blob store: a directory under the files-only prefix.
	legacyBlobs := mkStaleDir(t, dir, "shieldoo-gate-blobs", old)

	// Mirror main.go's New(Config{...}).
	j := New(Config{
		Dir:      dir,
		MaxAge:   time.Hour,
		Denylist: []string{"shieldoo-gate-blobs", socketName},
	})
	j.Sweep(time.Now())

	if exists(staleTrivy) {
		t.Error("stale shieldoo-trivy scratch dir must be reclaimed")
	}
	if !exists(freshStaging) {
		t.Error("fresh in-flight staging file must survive")
	}
	if !exists(socketPath) {
		t.Error("live gRPC socket must never be deleted")
	}
	if !exists(legacyBlobs) {
		t.Error("legacy /tmp push blob-store dir must survive (ADR-009, pending migration)")
	}
}
