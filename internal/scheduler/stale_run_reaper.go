package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/rs/zerolog/log"
)

// StaleRunThresholdFloor is the lower bound on the stale-run threshold. A scan that
// legitimately overruns its per-component budget must never be reaped out from under
// itself, so even a very short configured scan timeout still buys an hour of grace.
const StaleRunThresholdFloor = time.Hour

// staleRunTimeoutMultiplier scales the configured per-component scan timeout into the
// default stale threshold. Four attempts' worth of budget is well past any legitimate
// overrun (context deadline, DB write, audit flush) while still an order of magnitude
// below the 6h default rescan cadence, so a wedged row costs at most one skipped cycle.
const staleRunTimeoutMultiplier = 4

// DefaultStaleRunThreshold derives the stale-run threshold from the per-component scan
// timeout: max(4 x scanTimeout, 1h). With the default 5m timeout this is the 1h floor;
// an operator who raises the timeout past 15m gets a proportionally larger threshold
// without having to remember a second knob.
func DefaultStaleRunThreshold(scanTimeout time.Duration) time.Duration {
	threshold := staleRunTimeoutMultiplier * scanTimeout
	if threshold < StaleRunThresholdFloor {
		return StaleRunThresholdFloor
	}
	return threshold
}

// StaleRunReaperConfig configures the stale scan-run reaper.
type StaleRunReaperConfig struct {
	Interval  time.Duration // how often to sweep; default 15m
	Threshold time.Duration // age past which a pending/running row is considered wedged; default 1h
}

func (c StaleRunReaperConfig) withDefaults() StaleRunReaperConfig {
	if c.Interval <= 0 {
		c.Interval = 15 * time.Minute
	}
	if c.Threshold <= 0 {
		c.Threshold = DefaultStaleRunThreshold(0)
	}
	return c
}

// StaleRunReaper ages out scan_runs rows wedged in 'pending' or 'running'.
//
// A process restart mid-scan leaves the row in 'running' with no goroutine behind it.
// ManifestRescanScheduler.RunOnce excludes any component with such a row (see the
// NOT EXISTS predicate there), so one orphaned row silently disables scheduled rescans
// for that component forever — observed in production as scan_runs.id=355 wedging
// component 5 from 2026-06-04 until it was reaped by hand.
//
// This reaper is the backstop: it marks such rows 'failed' so the next rescan cycle
// picks the component back up. It deliberately does NOT touch components.last_scan_id.
// That pointer is only ever advanced on the success path (component.ScanService.Run
// calls SetLastScanID after UpdateScanRunStatus(StatusDone)), so a wedged pending or
// running row can never be the last_scan_id; repointing it here would rewrite scan
// history to hide the gap instead of surfacing it.
//
// scan_runs is not the audit log — UPDATE on it is permitted (CLAUDE.md invariant 5
// covers audit_log only, which this reaper never writes).
type StaleRunReaper struct {
	cfg   StaleRunReaperConfig
	db    *config.GateDB
	stop  chan struct{}
	doneC chan struct{}
}

// NewStaleRunReaper constructs the reaper.
func NewStaleRunReaper(cfg StaleRunReaperConfig, db *config.GateDB) *StaleRunReaper {
	return &StaleRunReaper{
		cfg:   cfg.withDefaults(),
		db:    db,
		stop:  make(chan struct{}),
		doneC: make(chan struct{}),
	}
}

// Start runs the reaper loop until Stop is called.
//
// A sweep runs immediately on startup, before the first tick: a restart is precisely
// when a run gets orphaned, so the process that comes back up is the one best placed to
// clean up after the one that died. The threshold still applies at startup rather than
// reaping everything in flight — in a multi-instance deployment another instance's
// live runs are visible in the same table.
func (r *StaleRunReaper) Start(ctx context.Context) {
	go func() {
		defer close(r.doneC)
		if _, err := r.RunOnce(ctx); err != nil {
			log.Warn().Err(err).Msg("stale_run_reaper: startup sweep failed")
		}
		t := time.NewTicker(r.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stop:
				return
			case <-t.C:
				if _, err := r.RunOnce(ctx); err != nil {
					log.Warn().Err(err).Msg("stale_run_reaper: cycle failed")
				}
			}
		}
	}()
}

// Stop signals the loop to exit; safe to call multiple times.
func (r *StaleRunReaper) Stop() {
	select {
	case <-r.stop:
		return
	default:
		close(r.stop)
	}
	<-r.doneC
}

// RunOnce performs a single sweep and returns the number of runs reaped.
//
// SELECT-then-UPDATE rather than a single blind UPDATE so each reap can be logged with
// the run id, component id and age that make it triageable. The UPDATE re-asserts the
// status predicate, so a scan that completes between the two statements is left alone.
func (r *StaleRunReaper) RunOnce(ctx context.Context) (int, error) {
	cutoff := time.Now().UTC().Add(-r.cfg.Threshold)

	type staleRow struct {
		ID          int64     `db:"id"`
		ComponentID int64     `db:"component_id"`
		Status      string    `db:"status"`
		StartedAt   time.Time `db:"started_at"`
	}
	var stale []staleRow
	if err := r.db.SelectContext(ctx, &stale,
		`SELECT id, component_id, status, started_at FROM scan_runs
		 WHERE status IN ('pending', 'running')
		   AND started_at < ?
		 ORDER BY id ASC`, cutoff); err != nil {
		return 0, fmt.Errorf("stale_run_reaper: selecting stale runs: %w", err)
	}
	if len(stale) == 0 {
		return 0, nil
	}

	now := time.Now().UTC()
	reaped := 0
	for _, row := range stale {
		res, err := r.db.ExecContext(ctx,
			`UPDATE scan_runs
			 SET status = 'failed', finished_at = ?, error_message = ?
			 WHERE id = ? AND status IN ('pending', 'running')`,
			now, "reaped: stuck in "+row.Status, row.ID)
		if err != nil {
			return reaped, fmt.Errorf("stale_run_reaper: marking run %d failed: %w", row.ID, err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return reaped, fmt.Errorf("stale_run_reaper: rows affected for run %d: %w", row.ID, err)
		}
		if affected == 0 {
			// The run reached a terminal status between the SELECT and the UPDATE.
			continue
		}
		reaped++
		log.Warn().
			Int64("run_id", row.ID).
			Int64("component_id", row.ComponentID).
			Str("stuck_status", row.Status).
			Dur("age", now.Sub(row.StartedAt).Round(time.Second)).
			Msg("stale_run_reaper: scan run stuck past threshold, marked failed")
	}
	return reaped, nil
}
