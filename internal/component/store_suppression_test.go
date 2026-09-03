package component_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// seedRunWithFindings creates one component, one done scan_run, and one finding per
// entry of versions (all for the same cve/package). Returns the component id, the run
// id, and the finding ids in the order the versions were supplied.
func seedRunWithFindings(t *testing.T, db *config.GateDB, name, cveID, pkg string, versions ...string) (componentID, runID int64, findingIDs []int64) {
	t.Helper()
	res, err := db.Exec(`INSERT INTO components (project_id, name, ecosystem, enabled)
	                     VALUES (1, ?, 'pypi', 1)`, name)
	require.NoError(t, err)
	componentID, err = res.LastInsertId()
	require.NoError(t, err)

	res, err = db.Exec(
		`INSERT INTO scan_runs
		   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format, sbom_sha256,
		    started_at, finished_at, scanner_status, critical_count, high_count, medium_count, low_count,
		    new_critical_count, new_high_count, component_count)
		 VALUES (?, 'upload', 'done', 'sboms/x.json', 0, 'cyclonedx-json', '',
		         datetime('now'), datetime('now'), 'ok', 0, 0, 0, 0, 0, 0, 0)`, componentID)
	require.NoError(t, err)
	runID, err = res.LastInsertId()
	require.NoError(t, err)

	for _, v := range versions {
		r, err := db.Exec(
			`INSERT INTO scan_findings
			   (scan_run_id, component_id, cve_id, package_name, package_version, ecosystem,
			    severity, detected_by, is_suppressed)
			 VALUES (?, ?, ?, ?, ?, 'go', 'HIGH', 'trivy', 0)`,
			runID, componentID, cveID, pkg, v)
		require.NoError(t, err)
		id, err := r.LastInsertId()
		require.NoError(t, err)
		findingIDs = append(findingIDs, id)
	}
	return
}

// suppressedFindingIDs returns the ids of the suppressed findings in a run.
func suppressedFindingIDs(t *testing.T, db *config.GateDB, runID int64) []int64 {
	t.Helper()
	var ids []int64
	require.NoError(t, db.Select(&ids,
		`SELECT id FROM scan_findings WHERE scan_run_id = ? AND is_suppressed = 1 ORDER BY id`, runID))
	return ids
}

func newTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestApplySuppression_IgnoreWithVersion_SuppressesOnlyMatchingVersion(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	// The production shape this exists for: the same CVE on the same package name at two
	// versions — one from the bundled trivy binary, one from our own build.
	componentID, runID, findings := seedRunWithFindings(t, db, "gate-image",
		"CVE-2026-9999", "stdlib", "1.24.6", "1.27.1")

	ig, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID:    componentID,
		CVEID:          "CVE-2026-9999",
		PackageName:    "stdlib",
		PackageVersion: "1.24.6",
		Reason:         "bundled trivy binary, not our build",
		CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)

	require.NoError(t, store.ApplySuppression(ctx, ig.ID, runID))

	assert.Equal(t, []int64{findings[0]}, suppressedFindingIDs(t, db, runID),
		"only the pinned version may be suppressed; our own 1.27.1 must stay visible")
}

func TestApplySuppression_IgnoreWithoutVersion_SuppressesAllVersions(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID, findings := seedRunWithFindings(t, db, "gate-image",
		"CVE-2026-9999", "stdlib", "1.24.6", "1.27.1")

	// CreateIgnore writes NULL for an empty package_version (nullIfEmpty).
	ig, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID:    componentID,
		CVEID:          "CVE-2026-9999",
		PackageName:    "stdlib",
		Reason:         "not exploitable in our usage",
		CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)

	var stored *string
	require.NoError(t, db.Get(&stored, `SELECT package_version FROM cve_ignores WHERE id = ?`, ig.ID))
	require.Nil(t, stored, "an empty package_version must be stored as NULL")

	require.NoError(t, store.ApplySuppression(ctx, ig.ID, runID))

	assert.Equal(t, findings, suppressedFindingIDs(t, db, runID),
		"a version-blind ignore keeps its historical per-package reach")
}

// A cve_ignores row written with a literal empty string rather than NULL — reachable
// from SQL written by hand and from any pre-existing row — must behave identically to
// the NULL case. This is the branch a careless SQL-side NULL check would get wrong.
func TestApplySuppression_IgnoreWithEmptyStringVersion_SuppressesAllVersions(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID, findings := seedRunWithFindings(t, db, "gate-image",
		"CVE-2026-9999", "stdlib", "1.24.6", "1.27.1")

	res, err := db.Exec(
		`INSERT INTO cve_ignores (component_id, cve_id, package_name, package_version,
		                          reason, created_by_email)
		 VALUES (?, 'CVE-2026-9999', 'stdlib', '', 'legacy row', 'ops@example.com')`, componentID)
	require.NoError(t, err)
	ignoreID, err := res.LastInsertId()
	require.NoError(t, err)

	require.NoError(t, store.ApplySuppression(ctx, ignoreID, runID))

	assert.Equal(t, findings, suppressedFindingIDs(t, db, runID),
		"empty string and NULL package_version must be the same scope")
}

// scan_findings.package_version is NOT NULL, so the only "no version" shape a finding
// can take is the empty string. A version-pinned ignore must not reach it.
func TestApplySuppression_IgnoreWithVersion_LeavesVersionlessFindingVisible(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID, findings := seedRunWithFindings(t, db, "gate-image",
		"CVE-2026-9999", "stdlib", "1.24.6", "")

	ig, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID:    componentID,
		CVEID:          "CVE-2026-9999",
		PackageName:    "stdlib",
		PackageVersion: "1.24.6",
		Reason:         "bundled trivy binary",
		CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)
	require.NoError(t, store.ApplySuppression(ctx, ig.ID, runID))

	assert.Equal(t, []int64{findings[0]}, suppressedFindingIDs(t, db, runID),
		"a finding with no package version must not be suppressed by a version-pinned ignore")
}

func TestClearSuppression_VersionPinnedIgnore_ClearsWhatItStamped(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID, _ := seedRunWithFindings(t, db, "gate-image",
		"CVE-2026-9999", "stdlib", "1.24.6", "1.27.1")
	ig, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID:    componentID,
		CVEID:          "CVE-2026-9999",
		PackageName:    "stdlib",
		PackageVersion: "1.24.6",
		Reason:         "bundled trivy binary",
		CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)
	require.NoError(t, store.ApplySuppression(ctx, ig.ID, runID))
	require.Len(t, suppressedFindingIDs(t, db, runID), 1)

	require.NoError(t, store.ClearSuppression(ctx, ig.ID, runID))
	assert.Empty(t, suppressedFindingIDs(t, db, runID))
}

func TestIgnoreMatchKey_EmptyVersion_ReturnsVersionBlindKey(t *testing.T) {
	assert.Equal(t, "CVE-1|pkg", component.IgnoreMatchKey("CVE-1", "pkg", ""))
}

func TestIgnoreMatchKey_WithVersion_ReturnsVersionedKey(t *testing.T) {
	assert.Equal(t, "CVE-1|pkg|1.2.3", component.IgnoreMatchKey("CVE-1", "pkg", "1.2.3"))
	assert.NotEqual(t, component.IgnoreMatchKey("CVE-1", "pkg", ""),
		component.IgnoreMatchKey("CVE-1", "pkg", "1.2.3"))
}

func TestFindActiveIgnoresForRun_VersionPinnedIgnore_KeyedByVersion(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	componentID, runID, _ := seedRunWithFindings(t, db, "gate-image", "CVE-2026-9999", "stdlib", "1.24.6")
	pinned, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID: componentID, CVEID: "CVE-2026-9999", PackageName: "stdlib",
		PackageVersion: "1.24.6", Reason: "bundled trivy", CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)
	blind, err := store.CreateIgnore(ctx, &component.Ignore{
		ComponentID: componentID, CVEID: "CVE-2026-8888", PackageName: "oras-go",
		Reason: "not exploitable", CreatedByEmail: "ops@example.com",
	})
	require.NoError(t, err)

	mapping, err := store.FindActiveIgnoresForRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, map[string]int64{
		"CVE-2026-9999|stdlib|1.24.6": pinned.ID,
		"CVE-2026-8888|oras-go":       blind.ID,
	}, mapping)
}

func TestUpdateScanRunStatus_RunningRun_TransitionsToDone(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	_, runID, _ := seedRunWithFindings(t, db, "gate-image", "CVE-1", "pkg")
	_, err := db.Exec(`UPDATE scan_runs SET status = 'running', finished_at = NULL WHERE id = ?`, runID)
	require.NoError(t, err)

	require.NoError(t, store.UpdateScanRunStatus(ctx, runID, component.StatusDone,
		map[string]string{"engine": "ok"}, "", 1, 2, 3, 4, 5, 6, 7))

	run, err := store.GetScanRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, component.StatusDone, run.Status)
	assert.Equal(t, int64(1), run.CriticalCount)
	assert.Equal(t, int64(7), run.ComponentCount)
}

func TestUpdateScanRunStatus_TerminalRun_RefusesAndKeepsRow(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)
	ctx := context.Background()

	_, runID, _ := seedRunWithFindings(t, db, "gate-image", "CVE-1", "pkg")
	_, err := db.Exec(
		`UPDATE scan_runs SET status = 'failed', error_message = 'reaped: stuck in running' WHERE id = ?`, runID)
	require.NoError(t, err)

	err = store.UpdateScanRunStatus(ctx, runID, component.StatusDone,
		map[string]string{"engine": "ok"}, "", 1, 2, 3, 4, 5, 6, 7)
	require.ErrorIs(t, err, component.ErrScanRunTerminal)

	run, err := store.GetScanRun(ctx, runID)
	require.NoError(t, err)
	assert.Equal(t, component.StatusFailed, run.Status)
	assert.Equal(t, "reaped: stuck in running", run.ErrorMessage)
	assert.Zero(t, run.CriticalCount, "a refused update must not write counters")
}

func TestUpdateScanRunStatus_UnknownRun_ReturnsTerminal(t *testing.T) {
	db := newTestDB(t)
	store := component.NewStore(db)

	err := store.UpdateScanRunStatus(context.Background(), 4242, component.StatusDone,
		nil, "", 0, 0, 0, 0, 0, 0, 0)
	require.ErrorIs(t, err, component.ErrScanRunTerminal)
}
