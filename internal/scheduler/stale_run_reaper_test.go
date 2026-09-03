package scheduler_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scheduler"
)

// seedStaleRun inserts one scan_run for componentID with the given status, started
// hoursAgo hours in the past, and returns its id.
func seedStaleRun(t *testing.T, db *config.GateDB, componentID int64, status string, hoursAgo int) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO scan_runs
		   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format,
		    sbom_sha256, started_at)
		 VALUES (?, 'rescan', ?, 'sboms/components/x.json', 0, 'cyclonedx-json', '',
		         datetime('now', ?))`,
		componentID, status, "-"+strconv.Itoa(hoursAgo)+" hours")
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

// seedReaperComponent inserts one enabled component and returns its id.
func seedReaperComponent(t *testing.T, db *config.GateDB, name string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO components (project_id, name, ecosystem, enabled) VALUES (1, ?, 'oci', 1)`,
		name)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func reaperTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type runState struct {
	Status       string  `db:"status"`
	ErrorMessage *string `db:"error_message"`
	FinishedAt   *string `db:"finished_at"`
}

func readRun(t *testing.T, db *config.GateDB, runID int64) runState {
	t.Helper()
	var st runState
	require.NoError(t, db.Get(&st,
		`SELECT status, error_message, finished_at FROM scan_runs WHERE id = ?`, runID))
	return st
}

// TestStaleRunReaper_StuckRunning_MarkedFailed reproduces production scan_runs.id=355:
// a 'running' row three months old with no goroutine behind it.
func TestStaleRunReaper_StuckRunning_MarkedFailed(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "scanner-bridge-image")
	runID := seedStaleRun(t, db, componentID, "running", 2160) // 90 days

	reaper := scheduler.NewStaleRunReaper(scheduler.StaleRunReaperConfig{
		Threshold: time.Hour,
	}, db)
	reaped, err := reaper.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, reaped)

	st := readRun(t, db, runID)
	assert.Equal(t, "failed", st.Status)
	require.NotNil(t, st.ErrorMessage)
	assert.Equal(t, "reaped: stuck in running", *st.ErrorMessage)
	assert.NotNil(t, st.FinishedAt, "reaped run must get a finished_at")
}

// TestStaleRunReaper_StuckPending_MarkedFailed covers the other in-flight status: a
// row written by Submit whose Run never started.
func TestStaleRunReaper_StuckPending_MarkedFailed(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "gate-image")
	runID := seedStaleRun(t, db, componentID, "pending", 5)

	reaper := scheduler.NewStaleRunReaper(scheduler.StaleRunReaperConfig{
		Threshold: time.Hour,
	}, db)
	reaped, err := reaper.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, reaped)

	st := readRun(t, db, runID)
	assert.Equal(t, "failed", st.Status)
	require.NotNil(t, st.ErrorMessage)
	assert.Equal(t, "reaped: stuck in pending", *st.ErrorMessage)
}

// TestStaleRunReaper_RecentRunning_Untouched asserts a scan that is legitimately in
// flight is never reaped out from under itself.
func TestStaleRunReaper_RecentRunning_Untouched(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "gate")
	runID := seedStaleRun(t, db, componentID, "running", 0)

	reaper := scheduler.NewStaleRunReaper(scheduler.StaleRunReaperConfig{
		Threshold: time.Hour,
	}, db)
	reaped, err := reaper.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, reaped)

	st := readRun(t, db, runID)
	assert.Equal(t, "running", st.Status)
	assert.Nil(t, st.ErrorMessage)
	assert.Nil(t, st.FinishedAt)
}

// TestStaleRunReaper_TerminalRuns_Untouched asserts old 'done' and 'failed' rows are
// left exactly as they are — the reaper only ever touches in-flight statuses.
func TestStaleRunReaper_TerminalRuns_Untouched(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "ui")
	doneID := seedStaleRun(t, db, componentID, "done", 5000)
	failedID := seedStaleRun(t, db, componentID, "failed", 5000)

	reaper := scheduler.NewStaleRunReaper(scheduler.StaleRunReaperConfig{
		Threshold: time.Hour,
	}, db)
	reaped, err := reaper.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, reaped)

	assert.Equal(t, "done", readRun(t, db, doneID).Status)
	assert.Nil(t, readRun(t, db, doneID).ErrorMessage)
	assert.Equal(t, "failed", readRun(t, db, failedID).Status)
	assert.Nil(t, readRun(t, db, failedID).ErrorMessage,
		"a pre-existing failed run must not be relabelled as reaped")
}

// TestStaleRunReaper_ReapedRun_LeavesLastScanIDAlone pins the deliberate omission:
// components.last_scan_id is only advanced on the success path, so the reaper must not
// repoint it. The wedged component keeps pointing at its last genuinely successful run,
// which is exactly the SBOM the next rescan cycle replays.
func TestStaleRunReaper_ReapedRun_LeavesLastScanIDAlone(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "scanner-bridge-image")
	lastGoodID := seedStaleRun(t, db, componentID, "done", 500)
	_, err := db.Exec(`UPDATE components SET last_scan_id = ? WHERE id = ?`, lastGoodID, componentID)
	require.NoError(t, err)
	seedStaleRun(t, db, componentID, "running", 2160)

	reaper := scheduler.NewStaleRunReaper(scheduler.StaleRunReaperConfig{
		Threshold: time.Hour,
	}, db)
	reaped, err := reaper.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, reaped)

	var lastScanID int64
	require.NoError(t, db.Get(&lastScanID, `SELECT last_scan_id FROM components WHERE id = ?`, componentID))
	assert.Equal(t, lastGoodID, lastScanID)
}

// TestStaleRunReaper_ReapedComponent_BecomesRescanEligible verifies the whole point of
// the reaper: marking the row 'failed' is by itself enough to put the component back
// into ManifestRescanScheduler.RunOnce's selection. The query below is the same
// predicate that scheduler uses.
func TestStaleRunReaper_ReapedComponent_BecomesRescanEligible(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "scanner-bridge-image")
	lastGoodID := seedStaleRun(t, db, componentID, "done", 500)
	_, err := db.Exec(`UPDATE components SET last_scan_id = ? WHERE id = ?`, lastGoodID, componentID)
	require.NoError(t, err)
	seedStaleRun(t, db, componentID, "running", 2160)

	eligible := func() []int64 {
		var ids []int64
		require.NoError(t, db.Select(&ids,
			`SELECT id FROM components
			 WHERE enabled = TRUE
			   AND NOT EXISTS (
			     SELECT 1 FROM scan_runs sr
			     WHERE sr.component_id = components.id
			       AND sr.status IN ('pending', 'running')
			   )`))
		return ids
	}
	require.Empty(t, eligible(), "wedged component must start out excluded")

	reaper := scheduler.NewStaleRunReaper(scheduler.StaleRunReaperConfig{
		Threshold: time.Hour,
	}, db)
	_, err = reaper.RunOnce(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []int64{componentID}, eligible(),
		"after reaping, the component must be selected by the rescan predicate again")
}

// TestStaleRunReaper_StartStop_RunsStartupSweep asserts Start reaps before the first
// tick (the ticker interval here is far longer than the test) and that Stop is clean.
func TestStaleRunReaper_StartStop_RunsStartupSweep(t *testing.T) {
	db := reaperTestDB(t)
	componentID := seedReaperComponent(t, db, "gate-image")
	runID := seedStaleRun(t, db, componentID, "running", 100)

	reaper := scheduler.NewStaleRunReaper(scheduler.StaleRunReaperConfig{
		Interval:  time.Hour,
		Threshold: time.Hour,
	}, db)
	reaper.Start(context.Background())
	// Stop blocks until the loop goroutine returns, which it can only do after the
	// startup sweep has finished — so this also serialises DB access for the
	// in-memory SQLite pool.
	reaper.Stop()
	reaper.Stop() // idempotent

	assert.Equal(t, "failed", readRun(t, db, runID).Status,
		"Start must sweep once before the first tick")
}

func TestDefaultStaleRunThreshold_ShortTimeout_ReturnsFloor(t *testing.T) {
	assert.Equal(t, time.Hour, scheduler.DefaultStaleRunThreshold(5*time.Minute))
	assert.Equal(t, time.Hour, scheduler.DefaultStaleRunThreshold(0))
	assert.Equal(t, time.Hour, scheduler.DefaultStaleRunThreshold(15*time.Minute))
}

func TestDefaultStaleRunThreshold_LongTimeout_ReturnsFourTimesTimeout(t *testing.T) {
	assert.Equal(t, 2*time.Hour, scheduler.DefaultStaleRunThreshold(30*time.Minute))
	assert.Equal(t, 4*time.Hour, scheduler.DefaultStaleRunThreshold(time.Hour))
}
