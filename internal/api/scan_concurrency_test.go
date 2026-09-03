package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// scanSchedulerCap bounds the number of ScanService.Run goroutines that
// can be in flight simultaneously. Pre-Phase 3 the gate spawned one per
// upload with no bound; an image-scan workload (10× more CVE hydrate
// calls per run) could trivially overload the gate. The semaphore caps
// this; the test pins the cap behaviour.
func TestScanScheduler_CapsConcurrentRuns(t *testing.T) {
	sc := newScanScheduler(2)
	var inFlight, peak int64
	var mu sync.Mutex
	hold := make(chan struct{})
	var wg sync.WaitGroup

	work := func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sc.Acquire(ctx); err != nil {
			t.Errorf("Acquire: %v", err)
			return
		}
		defer sc.Release()
		v := atomic.AddInt64(&inFlight, 1)
		mu.Lock()
		if v > peak {
			peak = v
		}
		mu.Unlock()
		<-hold
		atomic.AddInt64(&inFlight, -1)
	}

	// Launch 5 workers; cap is 2. Only 2 should be in flight at any time.
	wg.Add(5)
	for i := 0; i < 5; i++ {
		go work()
	}
	// Give the first cap-many workers time to start and pin their peak,
	// then assert no erroneous extra concurrency raced in.
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	got := peak
	mu.Unlock()
	if got != 2 {
		t.Errorf("peak concurrent runs = %d, want 2", got)
	}
	close(hold)
	wg.Wait()
}

// InFlight() must reflect the count of currently-acquired slots for
// monitoring (Prometheus gauge wires off it).
func TestScanScheduler_InFlight_TracksAcquireRelease(t *testing.T) {
	sc := newScanScheduler(4)
	if got := sc.InFlight(); got != 0 {
		t.Errorf("initial InFlight = %d, want 0", got)
	}
	ctx := context.Background()
	if err := sc.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := sc.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if got := sc.InFlight(); got != 2 {
		t.Errorf("after 2 Acquires, InFlight = %d, want 2", got)
	}
	sc.Release()
	if got := sc.InFlight(); got != 1 {
		t.Errorf("after 1 Release, InFlight = %d, want 1", got)
	}
	sc.Release()
	if got := sc.InFlight(); got != 0 {
		t.Errorf("after 2 Releases, InFlight = %d, want 0", got)
	}
}

// --- failUnscheduledRun -----------------------------------------------------
//
// Acquire fails only when the detached scan context is done: the 10 m budget expired
// with the semaphore saturated, or the process is shutting down. Before this path
// existed the goroutine simply returned, leaving a 'pending' scan_runs row with nothing
// behind it — which excludes its component from every scheduled rescan until the
// stale-run reaper clears it.

func concurrencyTestServer(t *testing.T) (*Server, *config.GateDB) {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	srv := NewServer(db, nil, nil, nil)
	srv.SetVulnDeps(VulnDeps{
		Store: component.NewStore(db),
		Audit: auth.NewAuditWriter(db),
	})
	return srv, db
}

// seedRun inserts one scan_run in the given status and returns its id.
func seedRun(t *testing.T, db *config.GateDB, status string) int64 {
	t.Helper()
	_, err := db.Exec(`INSERT INTO components (project_id, name, ecosystem, enabled) VALUES (1, 'c', 'oci', 1)`)
	require.NoError(t, err)
	res, err := db.Exec(
		`INSERT INTO scan_runs
		   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format,
		    sbom_sha256, started_at)
		 VALUES (1, 'upload', ?, 'sboms/components/x.json', 0, 'cyclonedx-json', '', ?)`,
		status, time.Now().UTC())
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func readRunStatus(t *testing.T, db *config.GateDB, runID int64) (string, string) {
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

func countAuditRows(t *testing.T, db *config.GateDB, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, db.Get(&n, `SELECT COUNT(*) FROM audit_log WHERE event_type = ?`, eventType))
	return n
}

func TestFailUnscheduledRun_PendingRun_MarkedFailedWithAuditRow(t *testing.T) {
	srv, db := concurrencyTestServer(t)
	runID := seedRun(t, db, "pending")

	srv.failUnscheduledRun(runID, context.DeadlineExceeded)

	status, msg := readRunStatus(t, db, runID)
	assert.Equal(t, "failed", status, "a run that never got a slot must not be left pending")
	assert.Contains(t, msg, "scan concurrency slot not acquired")
	assert.Contains(t, msg, context.DeadlineExceeded.Error(), "the cause belongs in the row an operator reads")
	assert.Equal(t, 1, countAuditRows(t, db, string(model.EventScanRunFailed)))
}

func TestFailUnscheduledRun_AlreadyReapedRun_LeavesTheReaperDiagnosis(t *testing.T) {
	srv, db := concurrencyTestServer(t)
	runID := seedRun(t, db, "pending")
	// The stale-run reaper closed the row while this goroutine sat on the semaphore.
	_, err := db.Exec(
		`UPDATE scan_runs SET status = 'failed', error_message = 'reaped: stuck in pending' WHERE id = ?`,
		runID)
	require.NoError(t, err)

	srv.failUnscheduledRun(runID, context.Canceled)

	status, msg := readRunStatus(t, db, runID)
	assert.Equal(t, "failed", status)
	assert.Equal(t, "reaped: stuck in pending", msg, "a terminal row keeps the diagnosis it was closed with")
	assert.Equal(t, 0, countAuditRows(t, db, string(model.EventScanRunFailed)),
		"audit_log is append-only, so a duplicate scan_run_failed could never be cleaned up")
}
