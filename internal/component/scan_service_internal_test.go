package component

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// markRunning is the one status write Run performs that no external test can drive
// through Run itself: the interleaving it guards against opens between Run's GetScanRun
// and this UPDATE, and there is no dependency call in between to hook. Testing it
// directly is what makes the third leg of "a reap is final" verifiable rather than
// merely asserted.

func markRunningTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedRunInStatus inserts a component plus one scan_run in the given status.
func seedRunInStatus(t *testing.T, db *config.GateDB, status string) *ScanRun {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO components (project_id, name, ecosystem, enabled) VALUES (1, 'gate-image', 'oci', 1)`)
	require.NoError(t, err)
	componentID, err := res.LastInsertId()
	require.NoError(t, err)

	res, err = db.Exec(
		`INSERT INTO scan_runs
		   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format,
		    sbom_sha256, started_at)
		 VALUES (?, 'rescan', ?, 'sboms/components/x.json', 0, 'cyclonedx-json', '', ?)`,
		componentID, status, time.Now().UTC())
	require.NoError(t, err)
	runID, err := res.LastInsertId()
	require.NoError(t, err)

	return &ScanRun{ID: runID, ComponentID: componentID, Status: status}
}

func readStatusAndError(t *testing.T, db *config.GateDB, runID int64) (string, string) {
	t.Helper()
	var row struct {
		Status       string  `db:"status"`
		ErrorMessage *string `db:"error_message"`
	}
	require.NoError(t, db.Get(&row, `SELECT status, error_message FROM scan_runs WHERE id = ?`, runID))
	if row.ErrorMessage == nil {
		return row.Status, ""
	}
	return row.Status, *row.ErrorMessage
}

func TestMarkRunning_PendingRun_TransitionsToRunning(t *testing.T) {
	db := markRunningTestDB(t)
	run := seedRunInStatus(t, db, StatusPending)
	svc := &scanServiceImpl{db: db}

	require.NoError(t, svc.markRunning(context.Background(), run))

	status, _ := readStatusAndError(t, db, run.ID)
	assert.Equal(t, StatusRunning, status)
}

func TestMarkRunning_ReapedBetweenReadAndStart_LeavesTheReapIntact(t *testing.T) {
	db := markRunningTestDB(t)
	run := seedRunInStatus(t, db, StatusPending)
	svc := &scanServiceImpl{db: db}

	// The stale-run reaper closes the row after Run read it as pending. `run` still
	// carries the stale in-memory status, which is exactly the state Run is in when it
	// reaches this write.
	_, err := db.Exec(
		`UPDATE scan_runs SET status = 'failed', finished_at = ?, error_message = ?
		 WHERE id = ? AND status IN ('pending', 'running')`,
		time.Now().UTC(), "reaped: stuck in pending", run.ID)
	require.NoError(t, err)

	err = svc.markRunning(context.Background(), run)

	require.Error(t, err, "a run closed underneath us must not be started")
	assert.True(t, errors.Is(err, ErrScanRunTerminal))

	status, msg := readStatusAndError(t, db, run.ID)
	assert.Equal(t, StatusFailed, status, "a blind write would have resurrected this to 'running'")
	assert.Equal(t, "reaped: stuck in pending", msg, "the reaper's diagnosis must survive")
}

func TestMarkRunning_AlreadyDoneRun_NotReopened(t *testing.T) {
	db := markRunningTestDB(t)
	run := seedRunInStatus(t, db, StatusPending)
	svc := &scanServiceImpl{db: db}

	_, err := db.Exec(`UPDATE scan_runs SET status = 'done' WHERE id = ?`, run.ID)
	require.NoError(t, err)

	require.ErrorIs(t, svc.markRunning(context.Background(), run), ErrScanRunTerminal)

	status, _ := readStatusAndError(t, db, run.ID)
	assert.Equal(t, StatusDone, status)
}
