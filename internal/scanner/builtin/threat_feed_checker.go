package builtin

import (
	"context"
	"database/sql"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/jmoiron/sqlx"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*ThreatFeedChecker)(nil)

// ThreatFeedChecker performs a fast-path SHA256 lookup against the local
// threat_feed DB table. A match returns VerdictMalicious immediately without
// any file I/O.
type ThreatFeedChecker struct {
	db *sqlx.DB
}

// NewThreatFeedChecker creates a new ThreatFeedChecker backed by db.
func NewThreatFeedChecker(db *sqlx.DB) *ThreatFeedChecker {
	return &ThreatFeedChecker{db: db}
}

func (c *ThreatFeedChecker) Name() string    { return "builtin-threat-feed" }
func (c *ThreatFeedChecker) Version() string { return "1.0.0" }
func (c *ThreatFeedChecker) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemDocker,
		scanner.EcosystemNuGet,
	}
}
func (c *ThreatFeedChecker) HealthCheck(_ context.Context) error { return nil }

// Scan looks up artifact.SHA256 in the threat_feed table.
// If found, it returns VerdictMalicious with confidence 1.0.
// If not found, it returns VerdictClean.
// On DB error, it fails open (returns VerdictClean) and records the error.
func (c *ThreatFeedChecker) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	var packageName string
	err := c.db.GetContext(ctx, &packageName,
		"SELECT package_name FROM threat_feed WHERE sha256 = ?", artifact.SHA256)

	if err == sql.ErrNoRows {
		return scanner.ScanResult{
			Verdict:    scanner.VerdictClean,
			Confidence: 1.0,
			ScannerID:  c.Name(),
		}, nil
	}
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: c.Name(),
			Error:     err,
		}, nil
	}

	return scanner.ScanResult{
		Verdict:    scanner.VerdictMalicious,
		Confidence: 1.0,
		Findings: []scanner.Finding{{
			Severity:    scanner.SeverityCritical,
			Category:    "threat-feed-hit",
			Description: "Artifact SHA256 matches known malicious package in threat feed: " + packageName,
		}},
		ScannerID: c.Name(),
	}, nil
}
