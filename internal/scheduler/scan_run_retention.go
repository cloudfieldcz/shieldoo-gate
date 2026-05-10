package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/rs/zerolog/log"
)

// ScanRunRetentionConfig holds the retention reaper configuration.
type ScanRunRetentionConfig struct {
	KeepN          int           // keep most recent N runs per component
	Interval       time.Duration // how often the reaper runs
	GracePeriod    time.Duration // skip runs younger than this (mid-read avoidance)
	BlobPathPrefix string        // BlobStore path prefix for orphan reclaim
}

func (c ScanRunRetentionConfig) withDefaults() ScanRunRetentionConfig {
	if c.KeepN <= 0 {
		c.KeepN = 100
	}
	if c.Interval <= 0 {
		c.Interval = time.Hour
	}
	if c.GracePeriod <= 0 {
		c.GracePeriod = 5 * time.Minute
	}
	if c.BlobPathPrefix == "" {
		c.BlobPathPrefix = "sboms/components/"
	}
	return c
}

// ScanRunRetentionReaper periodically deletes old scan_runs rows and unlinks their
// SBOM blobs. Pin-by-reference: runs referenced by a non-revoked cve_ignores or by
// any audit_log row are preserved.
type ScanRunRetentionReaper struct {
	cfg   ScanRunRetentionConfig
	db    *config.GateDB
	blob  cache.BlobStore
	stop  chan struct{}
	doneC chan struct{}
}

// NewScanRunRetentionReaper constructs a reaper.
func NewScanRunRetentionReaper(cfg ScanRunRetentionConfig, db *config.GateDB, blob cache.BlobStore) *ScanRunRetentionReaper {
	return &ScanRunRetentionReaper{
		cfg:   cfg.withDefaults(),
		db:    db,
		blob:  blob,
		stop:  make(chan struct{}),
		doneC: make(chan struct{}),
	}
}

// Start runs the reaper loop until Stop is called.
func (r *ScanRunRetentionReaper) Start(ctx context.Context) {
	go func() {
		defer close(r.doneC)
		t := time.NewTicker(r.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stop:
				return
			case <-t.C:
				if err := r.RunOnce(ctx); err != nil {
					log.Warn().Err(err).Msg("scan_run_retention: cycle failed")
				}
			}
		}
	}()
}

// Stop signals the loop to exit; safe to call multiple times.
func (r *ScanRunRetentionReaper) Stop() {
	select {
	case <-r.stop:
		return
	default:
		close(r.stop)
	}
	<-r.doneC
}

// RunOnce performs a single reaper cycle.
func (r *ScanRunRetentionReaper) RunOnce(ctx context.Context) error {
	// SQLite supports the canonical NOT EXISTS form via correlated subqueries on rowid,
	// but it does NOT support "ORDER BY/LIMIT inside NOT EXISTS subquery" cleanly; rather
	// than build dialect-specific CTE shapes, we do this in three round-trips:
	//   1. Per-component, find IDs of runs to keep (most recent N + pinned).
	//   2. SELECT the candidate ids that fall outside that set.
	//   3. DELETE by id; collect the blob_path values from step 2 and unlink.
	type compID struct {
		ID int64 `db:"id"`
	}
	var comps []compID
	if err := r.db.SelectContext(ctx, &comps, `SELECT id FROM components`); err != nil {
		return fmt.Errorf("scan_run_retention: list components: %w", err)
	}

	cutoff := time.Now().UTC().Add(-r.cfg.GracePeriod)
	totalDeleted := 0
	for _, c := range comps {
		deleted, err := r.reapComponent(ctx, c.ID, cutoff)
		if err != nil {
			log.Warn().Err(err).Int64("component_id", c.ID).Msg("scan_run_retention: component reap failed")
			continue
		}
		totalDeleted += deleted
	}
	if totalDeleted > 0 {
		log.Info().Int("deleted", totalDeleted).Msg("scan_run_retention: reaped runs")
	}
	return nil
}

func (r *ScanRunRetentionReaper) reapComponent(ctx context.Context, componentID int64, cutoff time.Time) (int, error) {
	type runRow struct {
		ID       int64  `db:"id"`
		BlobPath string `db:"sbom_blob_path"`
	}
	var keep []runRow
	if err := r.db.SelectContext(ctx, &keep,
		`SELECT id, sbom_blob_path FROM scan_runs
		 WHERE component_id = ?
		 ORDER BY id DESC LIMIT ?`, componentID, r.cfg.KeepN); err != nil {
		return 0, err
	}
	if len(keep) < r.cfg.KeepN {
		// Nothing to delete; already below keep threshold.
		return 0, nil
	}
	keepIDs := make(map[int64]struct{}, len(keep))
	for _, k := range keep {
		keepIDs[k.ID] = struct{}{}
	}

	// Load all candidate runs older than cutoff that are NOT in keepIDs and NOT pinned.
	var candidates []runRow
	if err := r.db.SelectContext(ctx, &candidates,
		`SELECT id, sbom_blob_path FROM scan_runs
		 WHERE component_id = ? AND started_at < ?
		   AND NOT EXISTS (SELECT 1 FROM cve_ignores ci
		                   WHERE ci.created_against_run_id = scan_runs.id
		                     AND ci.revoked_at IS NULL)
		   AND NOT EXISTS (SELECT 1 FROM audit_log al WHERE al.scan_run_id = scan_runs.id)`,
		componentID, cutoff); err != nil {
		return 0, err
	}
	deleted := 0
	for _, cand := range candidates {
		if _, ok := keepIDs[cand.ID]; ok {
			continue
		}
		// 1. DELETE row first (CASCADE removes scan_findings).
		if _, err := r.db.ExecContext(ctx, `DELETE FROM scan_runs WHERE id = ?`, cand.ID); err != nil {
			return deleted, err
		}
		// 2. Unlink blob (best-effort; orphan sweeper handles crash window).
		if cand.BlobPath != "" {
			if err := r.blob.DeleteBlob(ctx, cand.BlobPath); err != nil {
				log.Warn().Err(err).Str("path", cand.BlobPath).Msg("scan_run_retention: blob unlink (orphan)")
			}
		}
		deleted++
	}
	return deleted, nil
}
