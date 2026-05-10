package ai

import (
	"context"
	"fmt"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// FixPathInsight is a single "bump package vX → vY fixes N CVEs" recommendation.
type FixPathInsight struct {
	PackageName  string `json:"package_name"`
	FromVersion  string `json:"from_version"`
	ToVersion    string `json:"to_version"`
	FixedCount   int64  `json:"fixed_count"`
	TotalCritHigh int64 `json:"total_critical_high"`
	Summary      string `json:"summary"`
}

// FixPathAnalyzer derives "bump package X to Y to fix N CVEs" recommendations from
// scan_findings without any LLM call. Branded as "AI" in the UI for the gradient styling
// but the logic is pure SQL.
type FixPathAnalyzer struct {
	db *config.GateDB
}

// NewFixPathAnalyzer constructs a FixPathAnalyzer.
func NewFixPathAnalyzer(db *config.GateDB) *FixPathAnalyzer {
	return &FixPathAnalyzer{db: db}
}

// Analyze returns the top fix-path recommendation for a component (or nil when none).
func (a *FixPathAnalyzer) Analyze(ctx context.Context, runID int64) (*FixPathInsight, error) {
	type row struct {
		PackageName    string `db:"package_name"`
		PackageVersion string `db:"package_version"`
		FixedVersion   string `db:"fixed_version"`
		Count          int64  `db:"count"`
	}
	var rows []row
	err := a.db.SelectContext(ctx, &rows,
		`SELECT package_name, package_version, fixed_version, COUNT(*) AS count
		 FROM scan_findings
		 WHERE scan_run_id = ?
		   AND is_suppressed = FALSE
		   AND severity IN ('CRITICAL', 'HIGH')
		   AND fixed_version <> ''
		 GROUP BY package_name, package_version, fixed_version
		 ORDER BY count DESC LIMIT 1`, runID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	var totalCritHigh int64
	if err := a.db.GetContext(ctx, &totalCritHigh,
		`SELECT COUNT(*) FROM scan_findings
		 WHERE scan_run_id = ? AND is_suppressed = FALSE
		   AND severity IN ('CRITICAL','HIGH')`, runID); err != nil {
		return nil, err
	}
	return &FixPathInsight{
		PackageName:   r.PackageName,
		FromVersion:   r.PackageVersion,
		ToVersion:     r.FixedVersion,
		FixedCount:    r.Count,
		TotalCritHigh: totalCritHigh,
		Summary:       fmt.Sprintf("%d of %d CRITICAL/HIGH fixed by bumping %s %s → %s", r.Count, totalCritHigh, r.PackageName, r.PackageVersion, r.FixedVersion),
	}, nil
}
