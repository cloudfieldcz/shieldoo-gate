// Package scheduler implements background scheduling for artifact rescans.
package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// artifactRow holds the DB columns needed for rescan selection.
type artifactRow struct {
	ID          string `db:"id"`
	Ecosystem   string `db:"ecosystem"`
	Name        string `db:"name"`
	Version     string `db:"version"`
	SHA256      string `db:"sha256"`
	StoragePath string `db:"storage_path"`
	SizeBytes   int64  `db:"size_bytes"`
	UpstreamURL string `db:"upstream_url"`
}

// RescanScheduler processes manually triggered rescans (PENDING_SCAN).
// It runs on a background ticker but can be woken up immediately via Notify().
type RescanScheduler struct {
	db            *config.GateDB
	cache         cache.CacheStore
	scanEngine    *scanner.Engine
	policyEngine  *policy.Engine
	interval      time.Duration
	batchSize     int
	maxConcurrent int64
	sem           *semaphore.Weighted
	notify        chan struct{}
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// NewRescanScheduler creates a new scheduler with the given configuration.
func NewRescanScheduler(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	cfg config.RescanConfig,
) *RescanScheduler {
	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil || interval <= 0 {
		interval = 24 * time.Hour
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}

	maxConc := int64(cfg.MaxConcurrent)
	if maxConc <= 0 {
		maxConc = 5
	}

	return &RescanScheduler{
		db:            db,
		cache:         cacheStore,
		scanEngine:    scanEngine,
		policyEngine:  policyEngine,
		interval:      interval,
		batchSize:     batchSize,
		maxConcurrent: maxConc,
		sem:           semaphore.NewWeighted(maxConc),
		notify:        make(chan struct{}, 1),
	}
}

// Start begins the background scheduler goroutine.
func (s *RescanScheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.run(ctx)
	}()

	log.Info().
		Dur("interval", s.interval).
		Int("batch_size", s.batchSize).
		Int64("max_concurrent", s.maxConcurrent).
		Msg("rescan scheduler started")
}

// Notify wakes up the scheduler to process pending rescans immediately.
// Non-blocking: if a notification is already pending, the call is a no-op.
func (s *RescanScheduler) Notify() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Stop gracefully shuts down the scheduler and waits for in-flight scans.
func (s *RescanScheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	log.Info().Msg("rescan scheduler stopped")
}

// run is the main loop: tick or notify, run cycle, repeat.
func (s *RescanScheduler) run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runCycle(ctx)
		case <-s.notify:
			s.runCycle(ctx)
		}
	}
}

// runCycle selects artifacts due for rescan and processes them concurrently.
func (s *RescanScheduler) runCycle(ctx context.Context) {
	artifacts, err := s.selectArtifacts(ctx)
	if err != nil {
		log.Error().Err(err).Msg("rescan scheduler: failed to select artifacts")
		return
	}
	if len(artifacts) == 0 {
		log.Debug().Msg("rescan scheduler: no artifacts due for rescan")
		return
	}

	log.Info().Int("count", len(artifacts)).Msg("rescan scheduler: starting cycle")

	var wg sync.WaitGroup
	for _, art := range artifacts {
		if ctx.Err() != nil {
			break
		}
		if err := s.sem.Acquire(ctx, 1); err != nil {
			break
		}
		wg.Add(1)
		go func(a artifactRow) {
			defer wg.Done()
			defer s.sem.Release(1)
			s.rescanArtifact(ctx, a)
		}(art)
	}
	wg.Wait()

	log.Info().Int("count", len(artifacts)).Msg("rescan scheduler: cycle complete")
}

// selectArtifacts queries artifacts queued for manual rescan (PENDING_SCAN).
// Only manually triggered rescans are processed; automatic periodic rescans
// of CLEAN/SUSPICIOUS artifacts are not performed.
func (s *RescanScheduler) selectArtifacts(ctx context.Context) ([]artifactRow, error) {
	var rows []artifactRow
	err := s.db.SelectContext(ctx, &rows,
		`SELECT a.id, a.ecosystem, a.name, a.version, a.sha256, a.storage_path, a.size_bytes, a.upstream_url
		 FROM artifacts a
		 JOIN artifact_status s ON a.id = s.artifact_id
		 WHERE s.status = 'PENDING_SCAN'
		 ORDER BY a.last_accessed_at DESC
		 LIMIT ?`,
		s.batchSize,
	)
	if err != nil {
		return nil, fmt.Errorf("rescan scheduler: selecting artifacts: %w", err)
	}
	return rows, nil
}

// rescanArtifact performs the rescan pipeline for a single artifact:
// cache check -> scan -> policy evaluate -> update status + audit log.
func (s *RescanScheduler) rescanArtifact(ctx context.Context, art artifactRow) {
	// 1. Verify artifact still exists in cache.
	localPath, err := s.cache.Get(ctx, art.ID)
	if err != nil {
		if err == cache.ErrNotFound {
			// Artifact evicted from cache. Clear rescan_due_at, skip.
			log.Warn().Str("artifact", art.ID).Msg("rescan scheduler: artifact not in cache, skipping")
			s.clearRescanDueAt(art.ID)
			return
		}
		log.Error().Err(err).Str("artifact", art.ID).Msg("rescan scheduler: cache get error, skipping")
		return
	}

	// 2. Build scanner.Artifact.
	scanArtifact := scanner.Artifact{
		ID:          art.ID,
		Ecosystem:   scanner.Ecosystem(art.Ecosystem),
		Name:        art.Name,
		Version:     art.Version,
		LocalPath:   localPath,
		SHA256:      art.SHA256,
		SizeBytes:   art.SizeBytes,
		UpstreamURL: art.UpstreamURL,
	}

	// 3. Scan with all applicable scanners, excluding AI scanner (its results
	// are deterministic for the same artifact content — no value in re-running).
	results, scanErr := s.scanEngine.ScanAll(ctx, scanArtifact, "ai-scanner")
	if scanErr != nil {
		log.Error().Err(scanErr).Str("artifact", art.ID).Msg("rescan scheduler: scan error, preserving current status")
		s.updateRescanDueAt(art.ID, time.Now().UTC().Add(s.interval))
		return
	}

	// Log individual scanner results for observability.
	for _, sr := range results {
		l := log.Info().
			Str("artifact", art.ID).
			Str("scanner", sr.ScannerID).
			Str("verdict", string(sr.Verdict)).
			Float32("confidence", sr.Confidence).
			Dur("duration", sr.Duration)
		if sr.Error != nil {
			l = l.Err(sr.Error)
		}
		if len(sr.Findings) > 0 {
			l = l.Int("findings", len(sr.Findings))
		}
		l.Msg("rescan: scan result")
	}

	// 4. Policy evaluation (only when scan succeeded).
	decision := s.policyEngine.Evaluate(ctx, scanArtifact, results)

	log.Info().
		Str("artifact", art.ID).
		Str("action", string(decision.Action)).
		Str("reason", decision.Reason).
		Msg("rescan scheduler: policy decision")

	// 5. Update status + scan results + audit log in a transaction.
	now := time.Now().UTC()

	tx, err := s.db.Beginx()
	if err != nil {
		log.Error().Err(err).Str("artifact", art.ID).Msg("rescan scheduler: failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	switch decision.Action {
	case policy.ActionQuarantine, policy.ActionBlock:
		// Reclassify as quarantined.
		_, err = tx.Exec(
			`UPDATE artifact_status SET status = ?, quarantine_reason = ?, quarantined_at = ?, rescan_due_at = NULL WHERE artifact_id = ?`,
			string(model.StatusQuarantined), decision.Reason, now, art.ID,
		)
		if err != nil {
			log.Error().Err(err).Str("artifact", art.ID).Msg("rescan scheduler: failed to update status to quarantined")
			return
		}

		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Str("artifact", art.ID).Msg("rescan scheduler: commit failed")
			return
		}

		// Persist scan results (outside transaction, non-critical).
		_ = adapter.InsertScanResults(s.db, art.ID, results)

		// Audit log: quarantined (triggers alert automatically via hook).
		_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
			EventType:  model.EventQuarantined,
			ArtifactID: art.ID,
			Reason:     fmt.Sprintf("reclassified during scheduled rescan: %s", decision.Reason),
		})

	default:
		// ActionAllow: update status to CLEAN (no automatic next rescan).
		_, err = tx.Exec(
			`UPDATE artifact_status SET status = ?, quarantine_reason = '', quarantined_at = NULL, rescan_due_at = NULL WHERE artifact_id = ?`,
			string(model.StatusClean), art.ID,
		)
		if err != nil {
			log.Error().Err(err).Str("artifact", art.ID).Msg("rescan scheduler: failed to update status to clean")
			return
		}

		if err := tx.Commit(); err != nil {
			log.Error().Err(err).Str("artifact", art.ID).Msg("rescan scheduler: commit failed")
			return
		}

		// Persist scan results (outside transaction, non-critical).
		_ = adapter.InsertScanResults(s.db, art.ID, results)

		// Audit log: scanned.
		_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
			EventType:  model.EventScanned,
			ArtifactID: art.ID,
			Reason:     fmt.Sprintf("scheduled rescan: %s", decision.Reason),
		})
	}
}

// clearRescanDueAt removes the rescan_due_at for an artifact (e.g., evicted from cache).
func (s *RescanScheduler) clearRescanDueAt(artifactID string) {
	_, err := s.db.Exec(
		`UPDATE artifact_status SET rescan_due_at = NULL WHERE artifact_id = ?`,
		artifactID,
	)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("rescan scheduler: failed to clear rescan_due_at")
	}
}

// updateRescanDueAt sets the next rescan time for an artifact.
func (s *RescanScheduler) updateRescanDueAt(artifactID string, next time.Time) {
	_, err := s.db.Exec(
		`UPDATE artifact_status SET rescan_due_at = ? WHERE artifact_id = ?`,
		next, artifactID,
	)
	if err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("rescan scheduler: failed to update rescan_due_at")
	}
}
