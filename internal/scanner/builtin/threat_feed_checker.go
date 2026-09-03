package builtin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*ThreatFeedChecker)(nil)

// ThreatFeedChecker performs a fast-path SHA256 lookup against the local
// threat_feed DB table. A match returns VerdictMalicious immediately without
// any file I/O.
type ThreatFeedChecker struct {
	db *config.GateDB
	// feedEnabled mirrors threat_feed.enabled. The checker is registered
	// unconditionally, so without it HealthCheck could not tell a feed that is
	// deliberately switched off from one that is broken.
	feedEnabled bool
}

// NewThreatFeedChecker creates a new ThreatFeedChecker backed by db.
// feedEnabled is threat_feed.enabled from the configuration; it only affects
// health reporting, never scan verdicts.
func NewThreatFeedChecker(db *config.GateDB, feedEnabled bool) *ThreatFeedChecker {
	return &ThreatFeedChecker{db: db, feedEnabled: feedEnabled}
}

// ErrFeedEmpty is returned by HealthCheck when the threat feed is configured
// but the local table has no rows, i.e. the checker cannot detect anything.
var ErrFeedEmpty = errors.New("builtin-threat-feed: local threat feed is empty, every artifact is reported CLEAN without being checked")

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

// HealthCheck answers "can this scanner detect anything", not "how fresh is the
// feed". An empty local table means every lookup misses and every artifact comes
// back CLEAN, so the scanner is reported unhealthy — previously it certified
// itself healthy on a gate whose feed had been dead for weeks.
//
// Staleness is deliberately not checked here: a feed that loaded once and has
// gone stale still detects everything it contains, and the freshness question is
// answered by shieldoo_gate_threat_feed_last_success_timestamp_seconds.
//
// A disabled feed is healthy. The checker is registered unconditionally, so
// without that guard every deployment running threat_feed.enabled: false would
// report a permanently unhealthy scanner.
//
// This is reporting only: Engine.HealthCheck feeds GET /api/v1/health and
// nothing else, and the handler returns 200 regardless. Scan verdicts are
// untouched.
func (c *ThreatFeedChecker) HealthCheck(ctx context.Context) error {
	if !c.feedEnabled {
		return nil
	}

	var entries int64
	if err := c.db.GetContext(ctx, &entries, "SELECT COUNT(*) FROM threat_feed"); err != nil {
		return fmt.Errorf("builtin-threat-feed: counting threat feed entries: %w", err)
	}
	if entries == 0 {
		return ErrFeedEmpty
	}
	return nil
}

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
