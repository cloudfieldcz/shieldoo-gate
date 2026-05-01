// Package scheduler — version-diff retention loop.
//
// CLEAN rows in version_diff_results accumulate without bound and have no
// audit value beyond ~3 months. SUSPICIOUS+ rows are evidence and stay
// forever (until manually pruned). This scheduler runs a daily DELETE of
// CLEAN rows older than VersionDiffRetentionDays.
package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// VersionDiffRetentionDays is the maximum age (days) for CLEAN rows in
// version_diff_results. Hard-coded for now; can be config-driven later.
const VersionDiffRetentionDays = 90

// VersionDiffRetentionScheduler runs a daily DELETE of CLEAN rows older than
// VersionDiffRetentionDays. Mirrors the RescanScheduler shape (Start/Stop +
// internal runOnce).
type VersionDiffRetentionScheduler struct {
	db     *config.GateDB
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewVersionDiffRetentionScheduler returns a scheduler ready to Start.
func NewVersionDiffRetentionScheduler(db *config.GateDB) *VersionDiffRetentionScheduler {
	return &VersionDiffRetentionScheduler{db: db}
}

// Start launches the background goroutine: an immediate run, then every 24 h.
func (s *VersionDiffRetentionScheduler) Start() {
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
		Int("retention_days", VersionDiffRetentionDays).
		Msg("version-diff retention scheduler started")
}

// Stop cancels the background goroutine and waits for it to exit.
func (s *VersionDiffRetentionScheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	log.Info().Msg("version-diff retention scheduler stopped")
}

// runOnce executes a single retention pass. Internal but unexported tests
// in the same package call it directly to drive a deterministic prune.
func (s *VersionDiffRetentionScheduler) runOnce(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-VersionDiffRetentionDays * 24 * time.Hour)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM version_diff_results
		  WHERE verdict = 'CLEAN' AND diff_at < ?`,
		cutoff,
	)
	if err != nil {
		log.Warn().Err(err).Msg("version-diff retention: delete failed")
		return
	}
	rows, _ := res.RowsAffected()
	log.Info().Int64("rows_deleted", rows).Time("cutoff", cutoff).
		Msg("version-diff retention: pruned CLEAN rows")
}
