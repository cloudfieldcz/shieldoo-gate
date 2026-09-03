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
	Interval      time.Duration // default 6h
	MaxConcurrent int64         // default 4
	Timeout       time.Duration // per-component timeout; default 5m
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

// RescanEligibleComponentsQuery selects the components a rescan sweep will act on:
// enabled, and with no scan already in flight (a manual rescan, an upload, or a
// previous cycle). It is exported because StaleRunReaper's regression test asserts that
// reaping a wedged run puts its component back into this exact selection; a copy of the
// predicate in that test could silently drift from this one and stop being load-bearing.
//
// RescanEligibleComponent is its row shape, exported for the same reason: a redeclared
// struct with hand-copied `db` tags in the test would drift from the projection here.
const RescanEligibleComponentsQuery = `SELECT id, last_scan_id FROM components
	 WHERE enabled = TRUE
	   AND NOT EXISTS (
	     SELECT 1 FROM scan_runs sr
	     WHERE sr.component_id = components.id
	       AND sr.status IN ('pending', 'running')
	   )`

// RescanEligibleComponent is one row of RescanEligibleComponentsQuery. LastScanID is nil
// for a component that has never been scanned; the sweep skips those, since there is no
// SBOM to replay.
type RescanEligibleComponent struct {
	ID         int64  `db:"id"`
	LastScanID *int64 `db:"last_scan_id"`
}

// inFlightSkipWarnGrace is the floor on the grace period that splits the skip line by
// severity. Below the grace, an in-flight scan is almost certainly a manual rescan or an
// upload that merely overlapped the sweep; above it, the run has outlived every
// legitimate scan budget (the longest is the API's 10m detached context) and is a
// candidate wedge.
const inFlightSkipWarnGrace = 15 * time.Minute

// inFlightSkipGrace scales the floor by the per-component scan budget the operator has
// already configured, so raising rescan.timeout does not turn every legitimately slow
// scan into a WARN. No new knob and no coupling to the reaper: the scheduler already
// holds this timeout.
func (s *ManifestRescanScheduler) inFlightSkipGrace() time.Duration {
	grace := 2 * s.cfg.Timeout
	if grace < inFlightSkipWarnGrace {
		return inFlightSkipWarnGrace
	}
	return grace
}

// RunOnce performs a single rescan sweep with single-flight overlap protection.
func (s *ManifestRescanScheduler) RunOnce(ctx context.Context) {
	if !s.running.CompareAndSwap(false, true) {
		log.Info().Msg("manifest_rescan: previous cycle still running, skipping")
		return
	}
	defer s.running.Store(false)

	s.logInFlightSkips(ctx)

	var components []RescanEligibleComponent
	err := s.db.SelectContext(ctx, &components, RescanEligibleComponentsQuery)
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
// marked failed within its threshold, after which the line stops on its own.
// Suppressing repeats would reintroduce exactly the silence this exists to remove.
//
// Split by severity instead. Because the reaper clears a wedge within its threshold
// (<=1h) while this sweep only runs every 6h, in steady state almost every line here is
// a benign overlap with a manual rescan or an upload — so logging all of them at WARN
// would train the operator to ignore the one line that matters. Runs younger than
// inFlightSkipWarnGrace log at INFO; older ones log at WARN and carry stuck=true, so the
// candidate wedges are both loud and greppable. The 15m grace is an approximation: this
// scheduler does not know the reaper's configured threshold, but 15m already exceeds
// every legitimate scan budget (the longest is the API's 10m detached context).
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
	grace := s.inFlightSkipGrace()
	for _, r := range skipped {
		age := now.Sub(r.StartedAt).Round(time.Second)
		stuck := age > grace
		ev := log.Info()
		if stuck {
			ev = log.Warn()
		}
		ev.
			Int64("component_id", r.ComponentID).
			Int64("run_id", r.RunID).
			Str("run_status", r.Status).
			Str("age", age.String()).
			Str("grace", grace.String()).
			Bool("stuck", stuck).
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
