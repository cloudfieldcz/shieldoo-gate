// Package versiondiff implements the AI-driven version-diff scanner. It compares
// new artifacts against previously cached versions of the same package by sending
// both archive paths to the Python scanner-bridge over gRPC, where extraction and
// LLM analysis occur. The Go side handles allowlist guards, idempotency lookup,
// SHA256 verification, verdict mapping (MALICIOUS → SUSPICIOUS downgrade), and DB
// persistence.
//
// Phase 6a (this commit): skeleton only — Scan returns CLEAN unconditionally.
// Phase 6b wires the real flow.
package versiondiff

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
)

// Compile-time interface check.
var _ scanner.Scanner = (*VersionDiffScanner)(nil)

const (
	scannerName    = "version-diff"
	scannerVersion = "2.0.0"
)

// VersionDiffScanner performs AI-driven diff analysis between two consecutive
// versions of a package. It dials the scanner-bridge Unix socket on construction
// and reuses the connection across scans.
type VersionDiffScanner struct {
	db     *config.GateDB
	cache  cache.CacheStore
	cfg    config.VersionDiffConfig
	client pb.ScannerBridgeClient
	closer func() error
}

// NewVersionDiffScanner constructs the scanner and dials the bridge socket.
// On dial failure it returns an error so main.go can warn-log and skip
// registration (matches the AI scanner pattern in cmd/shieldoo-gate/main.go).
func NewVersionDiffScanner(db *config.GateDB, cs cache.CacheStore, cfg config.VersionDiffConfig) (*VersionDiffScanner, error) {
	if db == nil {
		return nil, fmt.Errorf("version-diff scanner: db is nil")
	}
	if cs == nil {
		return nil, fmt.Errorf("version-diff scanner: cache store is nil")
	}
	if cfg.BridgeSocket == "" {
		return nil, fmt.Errorf("version-diff scanner: bridge_socket is required when scanner is enabled")
	}

	client, closer, err := dialBridge(cfg.BridgeSocket)
	if err != nil {
		return nil, err
	}

	return &VersionDiffScanner{
		db:     db,
		cache:  cs,
		cfg:    cfg,
		client: client,
		closer: closer,
	}, nil
}

// Close releases the gRPC connection to the bridge.
func (s *VersionDiffScanner) Close() error {
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

func (s *VersionDiffScanner) Name() string    { return scannerName }
func (s *VersionDiffScanner) Version() string { return scannerVersion }

func (s *VersionDiffScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemNuGet,
		scanner.EcosystemMaven,
		scanner.EcosystemRubyGems,
	}
}

// HealthCheck verifies the bridge is reachable in addition to the DB.
func (s *VersionDiffScanner) HealthCheck(ctx context.Context) error {
	var n int
	if err := s.db.GetContext(ctx, &n, "SELECT 1"); err != nil {
		return fmt.Errorf("version-diff scanner: db: %w", err)
	}
	resp, err := s.client.HealthCheck(ctx, &pb.HealthRequest{})
	if err != nil {
		return fmt.Errorf("version-diff scanner: bridge: %w", err)
	}
	if !resp.Healthy {
		return fmt.Errorf("version-diff scanner: bridge reports unhealthy")
	}
	return nil
}

// Scan is currently a stub that returns CLEAN with zero confidence. Phase 6b
// implements: allowlist + size guard, DB previous-version lookup, idempotency
// cache hit, SHA256 verify, gRPC ScanArtifactDiff call, verdict mapping, audit
// log entry on downgrade, INSERT into version_diff_results.
func (s *VersionDiffScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()
	if s.isAllowlisted(artifact.Name) {
		return s.cleanResult(start, nil), nil
	}
	log.Debug().Str("artifact", artifact.ID).Msg("version-diff: skeleton stub returning CLEAN — Phase 6b not implemented yet")
	return s.cleanResult(start, nil), nil
}

// cleanResult builds a fail-open ScanResult. err non-nil → logged via Warn.
func (s *VersionDiffScanner) cleanResult(start time.Time, err error) scanner.ScanResult {
	if err != nil {
		log.Warn().Err(err).Msg("version-diff: fail-open")
	}
	return scanner.ScanResult{
		Verdict:        scanner.VerdictClean,
		Confidence:     0,
		ScannerID:      scannerName,
		ScannerVersion: scannerVersion,
		Duration:       time.Since(start),
		ScannedAt:      start,
		Error:          err,
	}
}

// isAllowlisted is a case-insensitive name match against cfg.Allowlist.
func (s *VersionDiffScanner) isAllowlisted(name string) bool {
	lower := strings.ToLower(name)
	for _, a := range s.cfg.Allowlist {
		if strings.ToLower(a) == lower {
			return true
		}
	}
	return false
}
