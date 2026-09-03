package component_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// memBlobStore is an in-memory cache.BlobStore. Only PutBlob/GetBlob are exercised by
// ScanService.Run; the rest satisfy the interface.
type memBlobStore struct{ blobs map[string][]byte }

var _ cache.BlobStore = (*memBlobStore)(nil)

func newMemBlobStore() *memBlobStore { return &memBlobStore{blobs: map[string][]byte{}} }

func (m *memBlobStore) PutBlob(_ context.Context, path string, data []byte) error {
	m.blobs[path] = data
	return nil
}

func (m *memBlobStore) GetBlob(_ context.Context, path string) ([]byte, error) {
	b, ok := m.blobs[path]
	if !ok {
		return nil, cache.ErrBlobNotFound
	}
	return b, nil
}

func (m *memBlobStore) DeleteBlob(_ context.Context, path string) error {
	delete(m.blobs, path)
	return nil
}

func (m *memBlobStore) StatBlob(_ context.Context, path string) (int64, error) {
	b, ok := m.blobs[path]
	if !ok {
		return 0, cache.ErrBlobNotFound
	}
	return int64(len(b)), nil
}

func (m *memBlobStore) GetBlobStream(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, cache.ErrBlobNotFound
}

// stubScanner returns a fixed finding set. before, when set, runs before the findings
// are handed back — the hook used to simulate something happening to the scan_runs row
// while the scan is in flight.
type stubScanner struct {
	findings []*component.ScanFinding
	before   func()
}

var _ component.ScannerInvoker = (*stubScanner)(nil)

func (s *stubScanner) Scan(context.Context, *component.ScanRun, []byte) (*component.ScanResult, error) {
	if s.before != nil {
		s.before()
	}
	return &component.ScanResult{
		Findings:       s.findings,
		ScannerStatus:  map[string]string{"engine": "stub"},
		ComponentCount: int64(len(s.findings)),
	}, nil
}

// recordingAudit captures the audit rows the scan service emits.
type recordingAudit struct{ entries []model.AuditEntry }

var _ component.AuditWriter = (*recordingAudit)(nil)

func (a *recordingAudit) WriteVulnEvent(_ context.Context, e model.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

// seedDoneRun inserts a finished scan_run for an existing component. Used to give the
// delta path a predecessor to compare against.
func seedDoneRun(t *testing.T, db *config.GateDB, componentID int64) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO scan_runs
		   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format,
		    sbom_sha256, started_at, finished_at, scanner_status, critical_count, high_count,
		    medium_count, low_count, new_critical_count, new_high_count, component_count)
		 VALUES (?, 'upload', 'done', 'sboms/prev.json', 0, 'cyclonedx-json', '',
		         datetime('now'), datetime('now'), 'ok', 0, 0, 0, 0, 0, 0, 0)`, componentID)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// seedPendingRun inserts a component plus a pending scan_run whose SBOM blob is already
// in the store, bypassing Submit's CycloneDX validation. previousRuns finished 'done'
// runs are inserted first, so their ids sort below the pending one.
func seedPendingRun(t *testing.T, db *config.GateDB, blobs *memBlobStore, name string, previousRuns int) (componentID, runID int64) {
	t.Helper()
	res, err := db.Exec(`INSERT INTO components (project_id, name, ecosystem, enabled)
	                     VALUES (1, ?, 'go', 1)`, name)
	require.NoError(t, err)
	componentID, err = res.LastInsertId()
	require.NoError(t, err)

	for i := 0; i < previousRuns; i++ {
		seedDoneRun(t, db, componentID)
	}

	body := []byte(`{"bomFormat":"CycloneDX"}`)
	sum := sha256.Sum256(body)
	path := "sboms/components/" + name + ".json"
	require.NoError(t, blobs.PutBlob(context.Background(), path, body))

	res, err = db.Exec(
		`INSERT INTO scan_runs
		   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format,
		    sbom_sha256, started_at, scanner_status, critical_count, high_count,
		    medium_count, low_count, new_critical_count, new_high_count, component_count)
		 VALUES (?, 'upload', 'pending', ?, ?, 'cyclonedx-json', ?,
		         datetime('now'), '', 0, 0, 0, 0, 0, 0, 0)`,
		componentID, path, len(body), hex.EncodeToString(sum[:]))
	require.NoError(t, err)
	runID, err = res.LastInsertId()
	require.NoError(t, err)
	return
}

func finding(cve, pkg, version, severity string) *component.ScanFinding {
	return &component.ScanFinding{
		CVEID:          cve,
		PackageName:    pkg,
		PackageVersion: version,
		Ecosystem:      "go",
		Severity:       severity,
		DetectedBy:     "stub",
	}
}

// The scan-time half of version-aware suppression: a pinned ignore must carry its scope
// into every subsequent run, not just the run it was created against. This is the path
// that decides whether a regression in our own binary stays visible.
func TestScanServiceRun_VersionPinnedIgnore_SuppressesOnlyMatchingVersion(t *testing.T) {
	db := newTestDB(t)
	blobs := newMemBlobStore()
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID := seedPendingRun(t, db, blobs, "gate-image", 0)
	_, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID: componentID, CVEID: "CVE-2026-9999", PackageName: "stdlib",
		PackageVersion: "1.24.6", Reason: "bundled trivy binary", CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)

	svc := component.NewScanService(component.ScanServiceConfig{}, component.ScanServiceDeps{
		DB:    db,
		Store: store,
		Blob:  blobs,
		Scanner: &stubScanner{findings: []*component.ScanFinding{
			finding("CVE-2026-9999", "stdlib", "1.24.6", component.SeverityHigh),
			finding("CVE-2026-9999", "stdlib", "1.27.1", component.SeverityHigh),
		}},
	})
	require.NoError(t, svc.Run(ctx, runID))

	rows, err := store.FindingsByRun(ctx, runID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	byVersion := map[string]bool{}
	for _, f := range rows {
		byVersion[f.PackageVersion] = f.IsSuppressed
	}
	assert.True(t, byVersion["1.24.6"], "the pinned version stays suppressed across runs")
	assert.False(t, byVersion["1.27.1"], "our own version must not inherit the trivy suppression")

	run, err := store.GetScanRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), run.HighCount, "the unsuppressed finding is counted")
}

func TestScanServiceRun_VersionBlindIgnore_SuppressesEveryVersion(t *testing.T) {
	db := newTestDB(t)
	blobs := newMemBlobStore()
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID := seedPendingRun(t, db, blobs, "gate-image", 0)
	_, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID: componentID, CVEID: "CVE-2026-9999", PackageName: "stdlib",
		Reason: "not exploitable in our usage", CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)

	svc := component.NewScanService(component.ScanServiceConfig{}, component.ScanServiceDeps{
		DB:    db,
		Store: store,
		Blob:  blobs,
		Scanner: &stubScanner{findings: []*component.ScanFinding{
			finding("CVE-2026-9999", "stdlib", "1.24.6", component.SeverityHigh),
			finding("CVE-2026-9999", "stdlib", "1.27.1", component.SeverityHigh),
		}},
	})
	require.NoError(t, svc.Run(ctx, runID))

	rows, err := store.FindingsByRun(ctx, runID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	for _, f := range rows {
		assert.True(t, f.IsSuppressed, "version-blind ignore keeps its per-package reach at scan time")
	}
	run, err := store.GetScanRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), run.HighCount)
}

// The reaper marks a wedged run failed. If the scan behind that row is still alive and
// finishes afterwards, it must not resurrect the row: doing so clears the reaper's
// error_message, advances last_scan_id, and — because the reap already made the
// component rescan-eligible — lets two runs compute their delta against the same
// predecessor, which surfaces as a spurious scan.new_critical alert.
func TestScanServiceRun_RunReapedMidScan_StaysReaped(t *testing.T) {
	db := newTestDB(t)
	blobs := newMemBlobStore()
	store := component.NewStore(db)
	ctx := context.Background()
	audit := &recordingAudit{}

	componentID, runID := seedPendingRun(t, db, blobs, "gate-image", 1) // one previous done run so the delta path really runs

	deltaCalls := 0
	svc := component.NewScanService(component.ScanServiceConfig{}, component.ScanServiceDeps{
		DB:    db,
		Store: store,
		Blob:  blobs,
		Audit: audit,
		Scanner: &stubScanner{
			findings: []*component.ScanFinding{
				finding("CVE-2026-1111", "oras-go", "1.2.3", component.SeverityCritical),
			},
			// Simulate the reaper firing while the scan is in flight, exactly as
			// StaleRunReaper.RunOnce writes it.
			before: func() {
				_, err := db.Exec(
					`UPDATE scan_runs SET status = 'failed', finished_at = datetime('now'),
					        error_message = 'reaped: stuck in running'
					 WHERE id = ? AND status IN ('pending', 'running')`, runID)
				require.NoError(t, err)
			},
		},
		DeltaFunc: func(context.Context, *component.ScanRun, *component.ScanRun, []*component.ScanFinding) (int64, int64, []model.AuditEntry, error) {
			deltaCalls++
			return 9, 9, []model.AuditEntry{{EventType: model.EventScanNewCritical}}, nil
		},
	})

	require.ErrorIs(t, svc.Run(ctx, runID), component.ErrScanRunTerminal)

	run, err := store.GetScanRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, component.StatusFailed, run.Status, "a reaped run must stay failed")
	assert.Equal(t, "reaped: stuck in running", run.ErrorMessage,
		"the reaper's diagnosis must survive")
	assert.Zero(t, run.NewCriticalCount, "delta counters must not be written onto a closed run")

	var lastScanID *int64
	require.NoError(t, db.Get(&lastScanID, `SELECT last_scan_id FROM components WHERE id = ?`, componentID))
	assert.Nil(t, lastScanID, "last_scan_id must not advance onto a reaped run")

	assert.Empty(t, audit.entries, "no regression alert may be emitted for a run that was never published")
	assert.Equal(t, 1, deltaCalls, "the delta was computed — its alerts just never reached the audit log")
}

func TestScanServiceRun_LiveRun_ClosesToDone(t *testing.T) {
	db := newTestDB(t)
	blobs := newMemBlobStore()
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID := seedPendingRun(t, db, blobs, "gate-image", 0)
	svc := component.NewScanService(component.ScanServiceConfig{}, component.ScanServiceDeps{
		DB:    db,
		Store: store,
		Blob:  blobs,
		Scanner: &stubScanner{findings: []*component.ScanFinding{
			finding("CVE-2026-1111", "oras-go", "1.2.3", component.SeverityCritical),
		}},
	})

	require.NoError(t, svc.Run(ctx, runID))

	run, err := store.GetScanRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, component.StatusDone, run.Status)
	assert.Equal(t, int64(1), run.CriticalCount)

	var lastScanID *int64
	require.NoError(t, db.Get(&lastScanID, `SELECT last_scan_id FROM components WHERE id = ?`, componentID))
	require.NotNil(t, lastScanID)
	assert.Equal(t, runID, *lastScanID, "the happy path must still advance last_scan_id")
}
