package versiondiff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*VersionDiffScanner)(nil)

const scannerName = "version-diff"
const scannerVersion = "1.0.0"

// VersionDiffScanner detects suspicious changes between package versions
// by comparing new artifacts against previously cached versions.
type VersionDiffScanner struct {
	db     *config.GateDB
	cache  cache.CacheStore
	cfg    config.VersionDiffConfig
	limits ExtractLimits
}

// NewVersionDiffScanner creates a new VersionDiffScanner.
// Performs stale temp directory cleanup on init (defense-in-depth).
func NewVersionDiffScanner(db *config.GateDB, cs cache.CacheStore, cfg config.VersionDiffConfig) (*VersionDiffScanner, error) {
	if db == nil {
		return nil, fmt.Errorf("version-diff scanner: db is nil")
	}
	if cs == nil {
		return nil, fmt.Errorf("version-diff scanner: cache store is nil")
	}

	s := &VersionDiffScanner{
		db:    db,
		cache: cs,
		cfg:   cfg,
		limits: ExtractLimits{
			MaxSizeMB: cfg.MaxExtractedSizeMB,
			MaxFiles:  cfg.MaxExtractedFiles,
		},
	}

	// Cleanup stale temp dirs from prior crashes.
	cleanupStaleTempDirs()

	return s, nil
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
		scanner.EcosystemGo,
	}
}

func (s *VersionDiffScanner) HealthCheck(ctx context.Context) error {
	var n int
	return s.db.GetContext(ctx, &n, "SELECT 1")
}

func (s *VersionDiffScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	// Helper to return CLEAN with optional error (fail-open).
	cleanResult := func(err error) (scanner.ScanResult, error) {
		if err != nil {
			log.Warn().Err(err).Str("artifact", artifact.ID).Msg("version-diff: fail-open")
		}
		return scanner.ScanResult{
			Verdict:        scanner.VerdictClean,
			Confidence:     0,
			ScannerID:      scannerName,
			ScannerVersion: scannerVersion,
			Duration:       time.Since(start),
			ScannedAt:      start,
			Error:          err,
		}, nil
	}

	// 1. Check allowlist
	if s.isAllowlisted(artifact.Name) {
		return cleanResult(nil)
	}

	// 2. Check artifact size limit (compressed)
	maxBytes := int64(s.cfg.MaxArtifactSizeMB) * 1024 * 1024
	if artifact.SizeBytes > maxBytes {
		log.Debug().Str("artifact", artifact.ID).Int64("size", artifact.SizeBytes).
			Msg("version-diff: skipping large artifact")
		return cleanResult(nil)
	}

	// 3. Apply sub-timeout
	timeout, parseErr := time.ParseDuration(s.cfg.ScannerTimeout)
	if parseErr != nil || timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 4. Query DB for previous CLEAN/SUSPICIOUS version
	var prevID, prevSHA256 string
	err := s.db.QueryRowContext(ctx,
		`SELECT a.id, a.sha256 FROM artifacts a
		 JOIN artifact_status s ON a.id = s.artifact_id
		 WHERE a.ecosystem = ? AND a.name = ? AND a.id != ?
		   AND s.status IN ('CLEAN', 'SUSPICIOUS')
		 ORDER BY a.cached_at DESC LIMIT 1`,
		string(artifact.Ecosystem), artifact.Name, artifact.ID,
	).Scan(&prevID, &prevSHA256)
	if err != nil {
		// No previous version → nothing to compare
		return cleanResult(nil)
	}

	// 5. Retrieve previous version from cache
	prevPath, err := s.cache.Get(ctx, prevID)
	if err != nil {
		return cleanResult(fmt.Errorf("cache get previous %s: %w", prevID, err))
	}

	// 6. Verify SHA256 of cached previous version (TOCTOU protection)
	if err := verifySHA256(prevPath, prevSHA256); err != nil {
		return cleanResult(fmt.Errorf("sha256 mismatch for %s: %w", prevID, err))
	}

	// 7. Extract both archives to temp directories
	newDir, err := os.MkdirTemp("", "vdiff-new-")
	if err != nil {
		return cleanResult(fmt.Errorf("create temp dir: %w", err))
	}
	defer os.RemoveAll(newDir)

	oldDir, err := os.MkdirTemp("", "vdiff-old-")
	if err != nil {
		return cleanResult(fmt.Errorf("create temp dir: %w", err))
	}
	defer os.RemoveAll(oldDir)

	if err := ExtractArchive(artifact.LocalPath, newDir, s.limits); err != nil {
		return cleanResult(fmt.Errorf("extract new artifact: %w", err))
	}
	if err := ExtractArchive(prevPath, oldDir, s.limits); err != nil {
		return cleanResult(fmt.Errorf("extract previous artifact: %w", err))
	}

	// 8. Run diff analyses
	entropySample := s.cfg.EntropySampleBytes
	if entropySample == 0 {
		entropySample = 8192
	}
	diffResult := RunDiff(oldDir, newDir, artifact.Ecosystem, s.cfg.Thresholds, s.cfg.SensitivePatterns, entropySample)

	// 9. Score findings → verdict
	verdict, confidence := scoreFindings(diffResult)

	// 10. Store diff results in DB (best-effort)
	s.storeDiffResult(ctx, artifact.ID, prevID, diffResult, verdict)

	return scanner.ScanResult{
		Verdict:        verdict,
		Confidence:     confidence,
		Findings:       diffResult.Findings,
		ScannerID:      scannerName,
		ScannerVersion: scannerVersion,
		Duration:       time.Since(start),
		ScannedAt:      start,
	}, nil
}

// isAllowlisted checks if the artifact name is in the configured allowlist.
func (s *VersionDiffScanner) isAllowlisted(name string) bool {
	lower := strings.ToLower(name)
	for _, a := range s.cfg.Allowlist {
		if strings.ToLower(a) == lower {
			return true
		}
	}
	return false
}

// scoreFindings maps findings to verdict + confidence.
// NOTE: Heuristic diff scanner MUST NOT produce MALICIOUS verdict.
// Per project conventions, scanner heuristics never escalate to MALICIOUS.
func scoreFindings(dr DiffResult) (scanner.Verdict, float32) {
	hasCritical := false
	hasHigh := false
	hasMedium := false

	for _, f := range dr.Findings {
		switch f.Severity {
		case scanner.SeverityCritical:
			hasCritical = true
		case scanner.SeverityHigh:
			hasHigh = true
		case scanner.SeverityMedium:
			hasMedium = true
		}
	}

	switch {
	case hasCritical:
		return scanner.VerdictSuspicious, 0.90
	case hasHigh:
		return scanner.VerdictSuspicious, 0.80
	case hasMedium:
		return scanner.VerdictSuspicious, 0.60
	default:
		return scanner.VerdictClean, 1.0
	}
}

// storeDiffResult inserts into version_diff_results (best-effort, errors logged not returned).
func (s *VersionDiffScanner) storeDiffResult(ctx context.Context, artifactID, prevArtifactID string, dr DiffResult, verdict scanner.Verdict) {
	findingsJSON, err := json.Marshal(dr.Findings)
	if err != nil {
		log.Warn().Err(err).Msg("version-diff: failed to marshal findings JSON")
		return
	}

	var newDepsJSON, sensChangesJSON *string
	if len(dr.NewDependencies) > 0 {
		b, _ := json.Marshal(dr.NewDependencies)
		s := string(b)
		newDepsJSON = &s
	}
	if len(dr.SensitiveChanges) > 0 {
		b, _ := json.Marshal(dr.SensitiveChanges)
		s := string(b)
		sensChangesJSON = &s
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO version_diff_results
		 (artifact_id, previous_artifact, diff_at, files_added, files_removed, files_modified,
		  size_ratio, max_entropy_delta, new_dependencies, sensitive_changes, verdict, findings_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		artifactID, prevArtifactID, time.Now().UTC(),
		dr.FilesAdded, dr.FilesRemoved, dr.FilesModified,
		dr.SizeRatio, dr.MaxEntropyDelta,
		newDepsJSON, sensChangesJSON,
		string(verdict), string(findingsJSON),
	)
	if err != nil {
		log.Warn().Err(err).Str("artifact", artifactID).Msg("version-diff: failed to store diff result")
	}
}

// verifySHA256 computes SHA256 of the file at path and compares to expected hex string.
func verifySHA256(path, expected string) error {
	if expected == "" {
		return nil // no expected hash to verify
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open for sha256: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read for sha256: %w", err)
	}

	actual := hex.EncodeToString(h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", actual, expected)
	}
	return nil
}

// cleanupStaleTempDirs removes stale vdiff-* temp directories older than 1 hour.
// Defense-in-depth against accumulation from SIGKILL/OOM.
func cleanupStaleTempDirs() {
	tmpDir := os.TempDir()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}

	cutoff := time.Now().Add(-1 * time.Hour)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !strings.HasPrefix(e.Name(), "vdiff-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(tmpDir, e.Name())
			if err := os.RemoveAll(path); err != nil {
				log.Debug().Err(err).Str("path", path).Msg("version-diff: failed to clean stale temp dir")
			} else {
				log.Debug().Str("path", path).Msg("version-diff: cleaned stale temp dir")
			}
		}
	}
}
