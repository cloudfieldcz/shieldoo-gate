// Package scheduler — scan_results retention loop.
//
// Each typosquat probe (and every other scan) appends a row to scan_results.
// Under typosquat-name flooding the table grows without bound; rows older
// than the retention window have minimal forensic value. This scheduler runs
// a daily DELETE of scan_results rows older than ScanResultsRetentionDays,
// excluding any row currently referenced by artifact_status.last_scan_id
// (those represent the artifact's *current* scan and must stay until a fresh
// scan replaces them).
//
// audit_log is intentionally NOT touched here: per CLAUDE.md it is
// append-only. The producer-side dedup in PersistTyposquatBlock is the
// audit_log growth control.
package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// ScanResultsRetentionDays is the maximum age (days) for rows in scan_results.
// Rows referenced by artifact_status.last_scan_id are retained even when older.
const ScanResultsRetentionDays = 90

// ScanResultsRetentionScheduler runs a daily DELETE of stale scan_results
// rows. Mirrors VersionDiffRetentionScheduler shape (Start/Stop + runOnce).
type ScanResultsRetentionScheduler struct {
	db     *config.GateDB
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewScanResultsRetentionScheduler returns a scheduler ready to Start.
func NewScanResultsRetentionScheduler(db *config.GateDB) *ScanResultsRetentionScheduler {
	return &ScanResultsRetentionScheduler{db: db}
}

// Start launches the background goroutine: an immediate run, then every 24 h.
func (s *ScanResultsRetentionScheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runOnce(ctx)
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runOnce(ctx)
			}
		}
	}()
	log.Info().
		Int("retention_days", ScanResultsRetentionDays).
		Msg("scan-results retention scheduler started")
}

// Stop cancels the background goroutine and waits for it to exit.
func (s *ScanResultsRetentionScheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	log.Info().Msg("scan-results retention scheduler stopped")
}

// runOnce executes a single retention pass.
func (s *ScanResultsRetentionScheduler) runOnce(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-ScanResultsRetentionDays * 24 * time.Hour)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM scan_results
		  WHERE scanned_at < ?
		    AND id NOT IN (
		      SELECT last_scan_id FROM artifact_status WHERE last_scan_id IS NOT NULL
		    )`,
		cutoff,
	)
	if err != nil {
		log.Warn().Err(err).Msg("scan-results retention: delete failed")
		return
	}
	rows, _ := res.RowsAffected()
	log.Info().Int64("rows_deleted", rows).Time("cutoff", cutoff).
		Msg("scan-results retention: pruned old rows")
}
