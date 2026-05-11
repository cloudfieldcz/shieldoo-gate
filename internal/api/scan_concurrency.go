package api

import (
	"context"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/semaphore"
)

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
			return
		}
		defer s.scanSched.Release()
		_ = s.vulnDeps.ScanService.Run(ctx, runID)
	}()
}
