package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
)

// ManifestRescanConfig controls the periodic rescan loop.
type ManifestRescanConfig struct {
	Interval       time.Duration // default 6h
	MaxConcurrent  int64         // default 4
	Timeout        time.Duration // per-component timeout; default 5m
}

func (c ManifestRescanConfig) withDefaults() ManifestRescanConfig {
	if c.Interval <= 0 {
		c.Interval = 6 * time.Hour
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 4
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Minute
	}
	return c
}

// ManifestRescanScheduler runs full-population rescans over enabled=1 components.
// Borrows the shape of internal/scheduler/rescan.go (ticker + semaphore) but the
// selection semantics are opposite: not a queue drain but a population sweep.
type ManifestRescanScheduler struct {
	cfg         ManifestRescanConfig
	db          *config.GateDB
	store       *component.Store
	scanService component.ScanService
	stop        chan struct{}
	doneC       chan struct{}
	running     atomic.Bool
}

// NewManifestRescanScheduler constructs the scheduler.
func NewManifestRescanScheduler(cfg ManifestRescanConfig, db *config.GateDB, store *component.Store, scanService component.ScanService) *ManifestRescanScheduler {
	return &ManifestRescanScheduler{
		cfg:         cfg.withDefaults(),
		db:          db,
		store:       store,
		scanService: scanService,
		stop:        make(chan struct{}),
		doneC:       make(chan struct{}),
	}
}

// Start runs the scheduler loop until Stop is called.
func (s *ManifestRescanScheduler) Start(ctx context.Context) {
	go func() {
		defer close(s.doneC)
		t := time.NewTicker(s.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stop:
				return
			case <-t.C:
				s.RunOnce(ctx)
			}
		}
	}()
}

// Stop signals the loop to exit.
func (s *ManifestRescanScheduler) Stop() {
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	<-s.doneC
}

// RunOnce performs a single rescan sweep with single-flight overlap protection.
func (s *ManifestRescanScheduler) RunOnce(ctx context.Context) {
	if !s.running.CompareAndSwap(false, true) {
		log.Info().Msg("manifest_rescan: previous cycle still running, skipping")
		return
	}
	defer s.running.Store(false)

	s.logInFlightSkips(ctx)

	type row struct {
		ID         int64  `db:"id"`
		LastScanID *int64 `db:"last_scan_id"`
	}
	var components []row
	// Skip components with an in-flight scan (manual rescan or previous cycle).
	err := s.db.SelectContext(ctx, &components,
		`SELECT id, last_scan_id FROM components
		 WHERE enabled = TRUE
		   AND NOT EXISTS (
		     SELECT 1 FROM scan_runs sr
		     WHERE sr.component_id = components.id
		       AND sr.status IN ('pending', 'running')
		   )`)
	if err != nil {
		log.Warn().Err(err).Msg("manifest_rescan: select components")
		return
	}
	if len(components) == 0 {
		return
	}

	sem := semaphore.NewWeighted(s.cfg.MaxConcurrent)
	var wg sync.WaitGroup
	for _, c := range components {
		if c.LastScanID == nil {
			// No prior scan to replay; CI will push the first SBOM.
			continue
		}
		if err := sem.Acquire(ctx, 1); err != nil {
			break
		}
		wg.Add(1)
		go func(componentID, runID int64) {
			defer sem.Release(1)
			defer wg.Done()
			s.rescanOne(ctx, componentID, runID)
		}(c.ID, *c.LastScanID)
	}
	wg.Wait()
}

// logInFlightSkips reports every enabled component that the selection query below is
// about to exclude because it has a pending/running scan_runs row.
//
// This is the defect that let scan_runs.id=355 wedge a component for three months: the
// exclusion was completely silent, so nothing distinguished "no rescan needed" from
// "rescans permanently disabled for this component". Only components with a
// last_scan_id are reported — one without has never had an SBOM pushed and is skipped
// by rescanOne anyway, so its exclusion carries no information.
//
// Deliberately not rate-limited. At the default 6h cadence this is four lines a day per
// affected component, and StaleRunReaper bounds it in time: a genuinely wedged row is
// marked failed within its threshold, after which the line stops on its own. A line for
// a scan that is merely concurrent (a manual rescan overlapping the sweep) carries a
// small age_seconds and is self-evidently benign. Suppressing repeats would reintroduce
// exactly the silence this exists to remove.
func (s *ManifestRescanScheduler) logInFlightSkips(ctx context.Context) {
	type skipRow struct {
		ComponentID int64     `db:"component_id"`
		RunID       int64     `db:"run_id"`
		Status      string    `db:"status"`
		StartedAt   time.Time `db:"started_at"`
	}
	var skipped []skipRow
	err := s.db.SelectContext(ctx, &skipped,
		`SELECT c.id AS component_id, sr.id AS run_id, sr.status, sr.started_at
		 FROM components c
		 JOIN scan_runs sr ON sr.component_id = c.id
		 WHERE c.enabled = TRUE
		   AND c.last_scan_id IS NOT NULL
		   AND sr.status IN ('pending', 'running')
		 ORDER BY sr.id ASC`)
	if err != nil {
		log.Warn().Err(err).Msg("manifest_rescan: select in-flight components")
		return
	}
	now := time.Now().UTC()
	for _, r := range skipped {
		log.Warn().
			Int64("component_id", r.ComponentID).
			Int64("run_id", r.RunID).
			Str("run_status", r.Status).
			Dur("age", now.Sub(r.StartedAt).Round(time.Second)).
			Msg("manifest_rescan: component skipped, scan already in flight")
	}
}

func (s *ManifestRescanScheduler) rescanOne(ctx context.Context, componentID, lastRunID int64) {
	// Re-use the previous SBOM blob: fetch it via ScanService.GetSBOM, re-submit as
	// a fresh upload with trigger=rescan. The upload path enforces structural validation
	// + writes a new pending row + invokes Run.
	body, err := s.scanService.GetSBOM(ctx, lastRunID)
	if err != nil {
		log.Warn().Err(err).Int64("run_id", lastRunID).Msg("manifest_rescan: get sbom")
		return
	}
	rctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	run, err := s.scanService.Submit(rctx, componentID, bytesReader(body), int64(len(body)),
		"application/vnd.cyclonedx+json", component.TriggerRescan, "scheduler")
	if err != nil {
		log.Warn().Err(err).Int64("component_id", componentID).Msg("manifest_rescan: submit")
		return
	}
	if err := s.scanService.Run(rctx, run.ID); err != nil {
		log.Warn().Err(err).Int64("run_id", run.ID).Msg("manifest_rescan: run")
	}
}

// bytesReader is a tiny adapter so we can pass a []byte to Submit without importing bytes.Reader twice.
type bytesReaderImpl struct {
	data []byte
	pos  int
}

func (r *bytesReaderImpl) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, eof
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func bytesReader(b []byte) *bytesReaderImpl { return &bytesReaderImpl{data: b} }

// eof is the stdlib io.EOF sentinel value, vendored so this package does not need
// to import "io" twice.
var eof = ioErrEOF()
