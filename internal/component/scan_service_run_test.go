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

// seedPendingRun inserts a component plus a pending scan_run whose SBOM blob is already
// in the store, bypassing Submit's CycloneDX validation.
func seedPendingRun(t *testing.T, db *config.GateDB, blobs *memBlobStore, name string) (componentID, runID int64) {
	t.Helper()
	res, err := db.Exec(`INSERT INTO components (project_id, name, ecosystem, enabled)
	                     VALUES (1, ?, 'go', 1)`, name)
	require.NoError(t, err)
	componentID, err = res.LastInsertId()
	require.NoError(t, err)

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

	componentID, runID := seedPendingRun(t, db, blobs, "gate-image")
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

	componentID, runID := seedPendingRun(t, db, blobs, "gate-image")
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
