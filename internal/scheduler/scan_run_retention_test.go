package scheduler_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scheduler"
)

// fakeBlobStore captures DeleteBlob calls so we can assert the reaper unlinks
// the right blob_paths and gracefully handles delete failures.
type fakeBlobStore struct {
	mu          sync.Mutex
	deleted     []string
	failOnPath  string
	stored      map[string][]byte
}

func newFakeBlobStore() *fakeBlobStore {
	return &fakeBlobStore{stored: make(map[string][]byte)}
}

func (f *fakeBlobStore) PutBlob(_ context.Context, path string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stored[path] = data
	return nil
}

func (f *fakeBlobStore) GetBlob(_ context.Context, path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if d, ok := f.stored[path]; ok {
		return d, nil
	}
	return nil, cache.ErrBlobNotFound
}

func (f *fakeBlobStore) DeleteBlob(_ context.Context, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if path == f.failOnPath {
		return errors.New("simulated blob delete failure")
	}
	f.deleted = append(f.deleted, path)
	delete(f.stored, path)
	return nil
}

func (f *fakeBlobStore) deletedPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.deleted))
	copy(out, f.deleted)
	return out
}

// seedComponentAndScans inserts a component and N scan_runs (oldest first),
// returning the inserted scan_run IDs in chronological order.
func seedComponentAndScans(t *testing.T, db *config.GateDB, n int) (componentID int64, runIDs []int64) {
	t.Helper()
	res, err := db.Exec(`INSERT INTO components (project_id, name, ecosystem, enabled)
	                     VALUES (1, 'billing-api', 'pypi', 1)`)
	require.NoError(t, err)
	componentID, err = res.LastInsertId()
	require.NoError(t, err)

	runIDs = make([]int64, 0, n)
	for i := 0; i < n; i++ {
		// older runs first; SQLite's id is auto-incremented so id order matches insert order.
		// started_at offset uses days for cleaner cutoff math.
		offset := -(n - i + 30) // ensure oldest is well outside any sane grace period
		path := "sboms/components/" + strconv.FormatInt(componentID, 10) + "/run-" + strconv.Itoa(i) + ".json"
		r, err := db.Exec(
			`INSERT INTO scan_runs
			   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format, sbom_sha256,
			    started_at, finished_at, scanner_status, critical_count, high_count, medium_count, low_count,
			    new_critical_count, new_high_count, component_count)
			 VALUES (?, 'upload', 'done', ?, 0, 'cyclonedx-json', '',
			         datetime('now', ?), datetime('now'), 'ok',
			         0, 0, 0, 0, 0, 0, 0)`,
			componentID, path, strconv.Itoa(offset)+" days",
		)
		require.NoError(t, err)
		id, err := r.LastInsertId()
		require.NoError(t, err)
		runIDs = append(runIDs, id)
	}
	return componentID, runIDs
}

// TestScanRunRetention_KeepsMostRecentN asserts the basic policy: with KeepN=3
// and 5 runs, the oldest 2 must be reaped and their blobs unlinked. The DB
// row deletion happens before the blob unlink (per CLAUDE.md retention contract),
// so even a blob-store failure leaves the row gone.
func TestScanRunRetention_KeepsMostRecentN(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, runIDs := seedComponentAndScans(t, db, 5)
	blob := newFakeBlobStore()

	reaper := scheduler.NewScanRunRetentionReaper(scheduler.ScanRunRetentionConfig{
		KeepN: 3,
	}, db, blob)
	require.NoError(t, reaper.RunOnce(context.Background()))

	var ids []int64
	require.NoError(t, db.Select(&ids, `SELECT id FROM scan_runs ORDER BY id ASC`))
	assert.Equal(t, runIDs[2:], ids, "should keep last 3 runs")
	assert.Len(t, blob.deletedPaths(), 2, "should unlink 2 oldest SBOMs")
}

// TestScanRunRetention_PinnedByIgnore_RetainsOldRow ensures the
// reaper preserves a scan_run referenced by a non-revoked cve_ignore even
// when that run is far older than KeepN's window. This is the
// "pin-by-reference" invariant from CLAUDE.md retention contract.
func TestScanRunRetention_PinnedByIgnore_RetainsOldRow(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	componentID, runIDs := seedComponentAndScans(t, db, 5)
	pinnedRun := runIDs[0] // the OLDEST — would otherwise be reaped

	// Pin via a cve_ignore that references this run and has not been revoked.
	_, err = db.Exec(`INSERT INTO cve_ignores
	   (component_id, cve_id, package_name, package_version, reason,
	    ai_draft_accepted, expires_at, created_against_run_id, created_by_email, created_at)
	 VALUES (?, 'CVE-2024-1', 'foo', '1.0', 'pinning this run',
	         0, NULL, ?, 'me@example.com', datetime('now'))`,
		componentID, pinnedRun,
	)
	require.NoError(t, err)

	reaper := scheduler.NewScanRunRetentionReaper(scheduler.ScanRunRetentionConfig{
		KeepN: 3,
	}, db, newFakeBlobStore())
	require.NoError(t, reaper.RunOnce(context.Background()))

	var stillPresent int
	require.NoError(t, db.Get(&stillPresent, `SELECT COUNT(*) FROM scan_runs WHERE id = ?`, pinnedRun))
	assert.Equal(t, 1, stillPresent, "pinned-by-ignore run must NOT be reaped")
}

// TestScanRunRetention_PinnedByAuditLog_RetainsOldRow is the parallel guard for
// audit_log references. The append-only audit log holds historical evidence;
// rows it references must never disappear.
func TestScanRunRetention_PinnedByAuditLog_RetainsOldRow(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, runIDs := seedComponentAndScans(t, db, 5)
	pinnedRun := runIDs[0]

	_, err = db.Exec(`INSERT INTO audit_log (ts, event_type, scan_run_id, reason)
	                  VALUES (datetime('now'), 'scan.new_critical', ?, 'historical')`,
		pinnedRun)
	require.NoError(t, err)

	reaper := scheduler.NewScanRunRetentionReaper(scheduler.ScanRunRetentionConfig{
		KeepN: 3,
	}, db, newFakeBlobStore())
	require.NoError(t, reaper.RunOnce(context.Background()))

	var stillPresent int
	require.NoError(t, db.Get(&stillPresent, `SELECT COUNT(*) FROM scan_runs WHERE id = ?`, pinnedRun))
	assert.Equal(t, 1, stillPresent, "audit-log-pinned run must NOT be reaped")
}

// TestScanRunRetention_BlobUnlinkFails_RowStillDeleted is the crash-safety
// scenario. The reaper deletes the DB row first; only then does it call
// DeleteBlob. If the blob storage call fails (network blip, ACL, missing key),
// the row is already gone — orphan_blob_sweeper picks up the stranded blob on
// next startup. This test simulates the partial failure and asserts the row
// is gone but the (would-be) blob path is captured by the orphan sweeper queue.
func TestScanRunRetention_BlobUnlinkFails_RowStillDeleted(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, runIDs := seedComponentAndScans(t, db, 5)
	doomedID := runIDs[0]

	// Look up the blob path to make the simulated failure target it specifically.
	var doomedPath string
	require.NoError(t, db.Get(&doomedPath, `SELECT sbom_blob_path FROM scan_runs WHERE id = ?`, doomedID))

	blob := newFakeBlobStore()
	blob.failOnPath = doomedPath // unlink of THIS path errors

	reaper := scheduler.NewScanRunRetentionReaper(scheduler.ScanRunRetentionConfig{
		KeepN: 3,
	}, db, blob)
	require.NoError(t, reaper.RunOnce(context.Background()))

	var stillPresent int
	require.NoError(t, db.Get(&stillPresent, `SELECT COUNT(*) FROM scan_runs WHERE id = ?`, doomedID))
	assert.Equal(t, 0, stillPresent,
		"row must be deleted even when blob unlink fails — orphan sweeper handles the stranded blob")
}

// TestScanRunRetention_BelowKeepN_NothingDeleted is the negative-control: when
// the component has fewer than KeepN runs, the reaper short-circuits and zero
// rows or blobs are touched. Catches regressions where someone "fixes" the
// reaper to be eager.
func TestScanRunRetention_BelowKeepN_NothingDeleted(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, _ = seedComponentAndScans(t, db, 2)
	blob := newFakeBlobStore()

	reaper := scheduler.NewScanRunRetentionReaper(scheduler.ScanRunRetentionConfig{
		KeepN: 5,
	}, db, blob)
	require.NoError(t, reaper.RunOnce(context.Background()))

	var n int
	require.NoError(t, db.Get(&n, `SELECT COUNT(*) FROM scan_runs`))
	assert.Equal(t, 2, n)
	assert.Empty(t, blob.deletedPaths())
}
