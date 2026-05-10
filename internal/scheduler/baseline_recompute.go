package scheduler

import (
	"context"
	"math"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component/ai"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/rs/zerolog/log"
)

// BaselineRecomputeConfig controls the daily 3σ baseline pre-aggregation.
type BaselineRecomputeConfig struct {
	// Interval between full recomputes; defaults to 24h. Aligns with the
	// detector's BaselineDays window — a sliding window doesn't need a
	// finer cadence for the static "expected CVE count per component".
	Interval time.Duration
}

// BaselineRecomputer warms ai.BaselineCache by aggregating CRITICAL+HIGH
// counts per component over the detector's BaselineDays window. Without it
// the AnomalyDetector recomputes that aggregate inside every Evaluate call;
// this scheduler turns it into a once-a-day O(N components) sweep.
type BaselineRecomputer struct {
	cfg      BaselineRecomputeConfig
	db       *config.GateDB
	detector *ai.AnomalyDetector
	cache    *ai.BaselineCache
	stop     chan struct{}
	doneC    chan struct{}
}

// NewBaselineRecomputer wires the scheduler. detector.Config() is consulted at
// every tick so config reloads are picked up without restart.
func NewBaselineRecomputer(cfg BaselineRecomputeConfig, db *config.GateDB, detector *ai.AnomalyDetector, cache *ai.BaselineCache) *BaselineRecomputer {
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	return &BaselineRecomputer{
		cfg:      cfg,
		db:       db,
		detector: detector,
		cache:    cache,
		stop:     make(chan struct{}),
		doneC:    make(chan struct{}),
	}
}

// Start launches the background loop. Cancel via the parent ctx or Stop().
// An immediate first sweep runs synchronously inside the goroutine so the cache
// is warm before the tick fires.
func (r *BaselineRecomputer) Start(ctx context.Context) {
	go func() {
		defer close(r.doneC)
		if err := r.RunOnce(ctx); err != nil {
			log.Warn().Err(err).Msg("baseline_recompute: initial sweep failed")
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
				if err := r.RunOnce(ctx); err != nil {
					log.Warn().Err(err).Msg("baseline_recompute: sweep failed")
				}
			}
		}
	}()
}

// Stop signals the loop to exit and waits for it to drain.
func (r *BaselineRecomputer) Stop() {
	select {
	case <-r.stop:
		// already stopped
	default:
		close(r.stop)
	}
	<-r.doneC
}

// RunOnce performs a single sweep across all enabled components.
func (r *BaselineRecomputer) RunOnce(ctx context.Context) error {
	cfg := r.detector.Config()
	since := time.Now().UTC().Add(-time.Duration(cfg.BaselineDays) * 24 * time.Hour)

	type aggRow struct {
		ComponentID int64   `db:"component_id"`
		SumTotal    int64   `db:"sum_total"`
		SumSq       float64 `db:"sum_sq"`
		Samples     int     `db:"samples"`
	}
	rows := []aggRow{}
	// One pass over scan_runs, GROUP BY component_id. Using SUM and SUM of squares
	// lets us compute variance without a self-join. NULL stddev (single sample) is
	// handled by the per-component loop below via the warm-up gate.
	err := r.db.SelectContext(ctx, &rows,
		`SELECT component_id,
		        COALESCE(SUM(critical_count + high_count), 0) AS sum_total,
		        COALESCE(SUM(CAST((critical_count + high_count) AS FLOAT) *
		                     CAST((critical_count + high_count) AS FLOAT)), 0) AS sum_sq,
		        COUNT(*) AS samples
		 FROM scan_runs
		 WHERE status = 'done' AND started_at > ?
		 GROUP BY component_id`,
		since)
	if err != nil {
		return err
	}
	updated := 0
	for _, ar := range rows {
		if ar.Samples == 0 {
			continue
		}
		mean := float64(ar.SumTotal) / float64(ar.Samples)
		// population variance: E[X^2] - E[X]^2
		variance := ar.SumSq/float64(ar.Samples) - mean*mean
		if variance < 0 {
			variance = 0 // numerical guard
		}
		stddev := math.Sqrt(variance)
		r.cache.Set(ar.ComponentID, mean, stddev, ar.Samples)
		updated++
	}
	log.Debug().Int("components", updated).Msg("baseline_recompute: cache warmed")
	return nil
}
