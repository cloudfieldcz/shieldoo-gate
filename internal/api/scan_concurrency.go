package api

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// scanSlotFailureWriteTimeout bounds the two statements failUnscheduledRun needs after
// Acquire gave up. It is short on purpose: the common cause of Acquire failing is
// process shutdown, and a janitorial write must not hold the exit open.
const scanSlotFailureWriteTimeout = 5 * time.Second

// scanSchedulerInFlight tracks how many ScanService.Run goroutines are
// currently mid-flight across upload + rescan paths. Exposed as a
// Prometheus gauge so operators can alert on sustained queue pressure.
var scanSchedulerInFlight = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "shieldoo_gate_vuln_scan_in_flight",
	Help: "Number of ScanService.Run goroutines currently executing (capped by vuln_scan.max_concurrent_scans).",
})

// scanScheduler bounds concurrent ScanService.Run invocations. Both the
// upload (handleScanUpload) and rescan (handleRescan) paths funnel
// goroutine kick-offs through Acquire/Release so an image-SBOM
// workload (10× heavier per scan than fs SBOMs) cannot fan out
// unbounded and OOM the gate.
type scanScheduler struct {
	sem      *semaphore.Weighted
	inFlight atomic.Int64
}

// newScanScheduler creates a scheduler with the given concurrency cap.
// cap <= 0 falls back to 4 — the default sized for a single-instance
// gate; tune via cfg.VulnScan.MaxConcurrentScans on resource-heavy
// deployments.
func newScanScheduler(cap int) *scanScheduler {
	if cap <= 0 {
		cap = 4
	}
	return &scanScheduler{sem: semaphore.NewWeighted(int64(cap))}
}

// Acquire blocks until a slot is available or ctx is cancelled.
func (s *scanScheduler) Acquire(ctx context.Context) error {
	if err := s.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	s.inFlight.Add(1)
	scanSchedulerInFlight.Inc()
	return nil
}

// Release returns one slot to the pool. Safe to call exactly once per
// successful Acquire.
func (s *scanScheduler) Release() {
	s.sem.Release(1)
	s.inFlight.Add(-1)
	scanSchedulerInFlight.Dec()
}

// InFlight returns the current count of acquired slots. Primarily for
// tests; production code should read the Prometheus gauge.
func (s *scanScheduler) InFlight() int64 {
	return s.inFlight.Load()
}

// SetScanConcurrency configures the cap on concurrent ScanService.Run
// goroutines. cap <= 0 falls back to 4. Safe to call once at startup;
// changes after wiring are not picked up.
func (s *Server) SetScanConcurrency(cap int) {
	s.scanSched = newScanScheduler(cap)
}

// runScanInBackground spawns ScanService.Run gated by the
// scan-concurrency semaphore. The handler returns 202 immediately; the
// goroutine blocks on Acquire when the cap is saturated, then runs.
// When the scheduler is unset (test scaffolding without
// SetScanConcurrency), the legacy unbounded spawn is used.
func (s *Server) runScanInBackground(runID int64) {
	if s.scanSched == nil {
		go func() { _ = s.vulnDeps.ScanService.Run(s.detachedCtx(), runID) }()
		return
	}
	go func() {
		ctx := s.detachedCtx()
		if err := s.scanSched.Acquire(ctx); err != nil {
			s.failUnscheduledRun(runID, err)
			return
		}
		defer s.scanSched.Release()
		_ = s.vulnDeps.ScanService.Run(ctx, runID)
	}()
}

// failUnscheduledRun closes a scan_run that never got a concurrency slot.
//
// Acquire fails only when the detached scan context is done: the hardcoded 10 m budget
// in detachedCtx expired while the semaphore stayed saturated, or the process is
// shutting down. Either way the row is left 'pending' with nothing behind it — the same
// shape a restart mid-scan leaves, and the shape that excludes the component from every
// scheduled rescan (ManifestRescanScheduler.RunOnce's in-flight predicate) until the
// stale-run reaper clears it up to an hour later. The reaper is the backstop; this is
// the source.
//
// The write needs a fresh context — the one Acquire failed on is already done.
func (s *Server) failUnscheduledRun(runID int64, cause error) {
	if s.vulnDeps.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanSlotFailureWriteTimeout)
	defer cancel()

	run, err := s.vulnDeps.Store.GetScanRun(ctx, runID)
	if err != nil {
		log.Warn().Err(err).Int64("run_id", runID).
			Msg("api: no concurrency slot for scan run and the run could not be read back")
		return
	}
	reason := "scan concurrency slot not acquired: " + cause.Error()
	if err := s.vulnDeps.Store.UpdateScanRunStatus(ctx, runID, component.StatusFailed,
		nil, reason, 0, 0, 0, 0, 0, 0, 0); err != nil {
		// ErrScanRunTerminal means the row was already closed — in practice reaped
		// while this goroutine sat on the semaphore. Leave the reaper's diagnosis in
		// place and write no audit row: audit_log is append-only (CLAUDE.md invariant
		// 5), so a duplicate scan_run_failed could never be cleaned up afterwards.
		if !errors.Is(err, component.ErrScanRunTerminal) {
			log.Warn().Err(err).Int64("run_id", runID).
				Msg("api: no concurrency slot for scan run and the run could not be closed")
		}
		return
	}

	log.Warn().
		Err(cause).
		Int64("run_id", runID).
		Int64("component_id", run.ComponentID).
		Msg("api: scan run closed as failed, no concurrency slot became available")

	if s.vulnDeps.Audit != nil {
		_ = s.vulnDeps.Audit.WriteVulnEvent(ctx, model.AuditEntry{
			EventType:   model.EventScanRunFailed,
			ComponentID: &run.ComponentID,
			ScanRunID:   &runID,
			Reason:      reason,
		})
	}
}
