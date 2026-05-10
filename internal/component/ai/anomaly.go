// Package ai implements the AI surfaces for the vulnerability-scan feature.
// AnomalyDetector and FixPathAnalyzer are pure Go (no LLM calls). IgnoreReasonDrafter
// is a gRPC client to the Python scanner-bridge sidecar.
package ai

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// Anomaly is a 3σ-deviation event recorded against a Component's CVE-count baseline.
type Anomaly struct {
	ID               int64     `db:"id" json:"id"`
	ComponentID      int64     `db:"component_id" json:"component_id"`
	DetectedAt       time.Time `db:"detected_at" json:"detected_at"`
	TriggeringRunID  *int64    `db:"triggering_run_id" json:"triggering_run_id,omitempty"`
	SeverityDelta    int64     `db:"severity_delta" json:"severity_delta"`
	BaselineMean     float64   `db:"baseline_mean" json:"baseline_mean"`
	BaselineStddev   float64   `db:"baseline_stddev" json:"baseline_stddev"`
	Sigma            float64   `db:"sigma" json:"sigma"`
	Summary          string    `db:"summary" json:"summary"`
}

// AnomalyConfig controls AnomalyDetector thresholds.
type AnomalyConfig struct {
	BaselineDays       int     // window for baseline computation, default 30
	MinBaselineSamples int     // warm-up gate, default 7
	SigmaThreshold     float64 // default 3.0
}

func (c AnomalyConfig) withDefaults() AnomalyConfig {
	if c.BaselineDays <= 0 {
		c.BaselineDays = 30
	}
	if c.MinBaselineSamples <= 0 {
		c.MinBaselineSamples = 7
	}
	if c.SigmaThreshold <= 0 {
		c.SigmaThreshold = 3.0
	}
	return c
}

// AnomalyAuditWriter is the audit interface used by the detector.
type AnomalyAuditWriter interface {
	WriteVulnEvent(ctx context.Context, e model.AuditEntry) error
}

// AnomalyDetector computes 3σ baseline events.
type AnomalyDetector struct {
	cfg   AnomalyConfig
	db    *config.GateDB
	audit AnomalyAuditWriter

	// baselineCache, if non-nil, is consulted before the per-Evaluate SQL.
	// Pre-warmed by the daily baseline_recompute scheduler.
	baselineCache *BaselineCache
}

// NewAnomalyDetector constructs an AnomalyDetector.
func NewAnomalyDetector(cfg AnomalyConfig, db *config.GateDB, audit AnomalyAuditWriter) *AnomalyDetector {
	return &AnomalyDetector{cfg: cfg.withDefaults(), db: db, audit: audit}
}

// WithBaselineCache wires the optional baseline pre-aggregation cache.
// When set, Evaluate skips the per-call window SQL whenever a fresh baseline is
// available — the scheduler refreshes the cache on a daily cadence. Older or
// missing entries fall back to the live SQL path so correctness is preserved
// when the scheduler is disabled or has not yet run.
func (d *AnomalyDetector) WithBaselineCache(c *BaselineCache) *AnomalyDetector {
	d.baselineCache = c
	return d
}

// Config returns the resolved AnomalyConfig (with defaults applied). Used by
// the scheduler so it computes baselines using the same window and warm-up
// thresholds as live evaluation.
func (d *AnomalyDetector) Config() AnomalyConfig { return d.cfg }

// DB returns the underlying database handle. Exposed for the scheduler so it
// can run the same baseline aggregation query without re-plumbing the handle.
func (d *AnomalyDetector) DB() *config.GateDB { return d.db }

// baselineSample is the aggregated CRITICAL+HIGH count for one historical run.
type baselineSample struct {
	Total int64 `db:"total"`
}

// Evaluate inspects the just-finished run and persists an anomaly when the CVE-count
// delta exceeds SigmaThreshold standard deviations of the BaselineDays-window mean.
// Idempotent per (component_id, triggering_run_id).
func (d *AnomalyDetector) Evaluate(ctx context.Context, componentID, runID int64, currentCriticalHigh int64) (*Anomaly, error) {
	anomalyEvaluatedTotal.Inc()
	var (
		mean, std    float64
		samples      int
		fromCache    bool
	)
	if d.baselineCache != nil {
		if e, ok := d.baselineCache.Get(componentID); ok {
			mean, std, samples = e.Mean, e.Stddev, e.Samples
			fromCache = true
		}
	}
	if !fromCache {
		since := time.Now().UTC().Add(-time.Duration(d.cfg.BaselineDays) * 24 * time.Hour)
		rows := []baselineSample{}
		err := d.db.SelectContext(ctx, &rows,
			`SELECT (critical_count + high_count) AS total FROM scan_runs
			 WHERE component_id = ? AND status = 'done' AND started_at > ? AND id < ?`,
			componentID, since, runID)
		if err != nil {
			return nil, err
		}
		samples = len(rows)
		mean, std = meanStddev(rows)
	}
	if samples < d.cfg.MinBaselineSamples {
		return nil, nil // warm-up
	}
	if std <= 0 {
		return nil, nil
	}
	sigma := (float64(currentCriticalHigh) - mean) / std
	if sigma < d.cfg.SigmaThreshold {
		return nil, nil
	}
	// Idempotency check.
	var existing int
	if err := d.db.GetContext(ctx, &existing,
		`SELECT COUNT(*) FROM anomalies WHERE component_id = ? AND triggering_run_id = ?`,
		componentID, runID); err != nil {
		return nil, err
	}
	if existing > 0 {
		return nil, nil
	}
	delta := currentCriticalHigh - int64(mean)
	summary := fmt.Sprintf("Spike: %d CRITICAL+HIGH (%.1fσ above %.1f baseline)", currentCriticalHigh, sigma, mean)
	anomalyDetectedTotal.Inc()
	res, err := d.db.ExecContext(ctx,
		`INSERT INTO anomalies (component_id, triggering_run_id, severity_delta, baseline_mean, baseline_stddev, sigma, summary)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		componentID, runID, delta, mean, std, sigma, summary)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if d.audit != nil {
		cid := componentID
		rid := runID
		_ = d.audit.WriteVulnEvent(ctx, model.AuditEntry{
			EventType:    model.EventScanAnomaly,
			ComponentID:  &cid,
			ScanRunID:    &rid,
			Reason:       summary,
			MetadataJSON: fmt.Sprintf(`{"sigma":%.2f,"baseline_mean":%.2f}`, sigma, mean),
		})
	}
	return &Anomaly{
		ID:              id,
		ComponentID:     componentID,
		TriggeringRunID: &runID,
		SeverityDelta:   delta,
		BaselineMean:    mean,
		BaselineStddev:  std,
		Sigma:           sigma,
		Summary:         summary,
	}, nil
}

func meanStddev(samples []baselineSample) (mean, stddev float64) {
	if len(samples) == 0 {
		return 0, 0
	}
	var sum int64
	for _, s := range samples {
		sum += s.Total
	}
	mean = float64(sum) / float64(len(samples))
	var sqSum float64
	for _, s := range samples {
		d := float64(s.Total) - mean
		sqSum += d * d
	}
	stddev = math.Sqrt(sqSum / float64(len(samples)))
	return mean, stddev
}

// ListAnomalies returns recent anomalies not yet acknowledged by viewer.
func ListAnomalies(ctx context.Context, db *config.GateDB, viewerEmail string, limit int) ([]*Anomaly, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	since := time.Now().UTC().Add(-14 * 24 * time.Hour)
	rows := []Anomaly{}
	err := db.SelectContext(ctx, &rows,
		`SELECT id, component_id, detected_at, triggering_run_id,
		        severity_delta, baseline_mean, baseline_stddev, sigma, summary
		 FROM anomalies a
		 WHERE a.detected_at > ?
		   AND NOT EXISTS (SELECT 1 FROM anomaly_acknowledgments aa
		                   WHERE aa.anomaly_id = a.id AND aa.user_email = ?)
		 ORDER BY a.detected_at DESC LIMIT ?`,
		since, viewerEmail, limit)
	if err != nil {
		return nil, err
	}
	out := make([]*Anomaly, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// AcknowledgeAnomaly inserts a per-user acknowledgement row.
func AcknowledgeAnomaly(ctx context.Context, db *config.GateDB, anomalyID int64, viewerEmail string) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO anomaly_acknowledgments (anomaly_id, user_email, acknowledged_at)
		 VALUES (?, ?, ?) ON CONFLICT DO NOTHING`,
		anomalyID, viewerEmail, time.Now().UTC())
	return err
}
