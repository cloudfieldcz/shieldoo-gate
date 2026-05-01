// Package versiondiff implements the AI-driven version-diff scanner. It compares
// new artifacts against a previously cached version of the same package by
// sending both archive paths to the Python scanner-bridge over gRPC. Extraction
// and LLM analysis happen in the bridge; the Go side handles allowlist guards,
// idempotency lookup, SHA256 verification, verdict mapping (MALICIOUS →
// SUSPICIOUS downgrade, MinConfidence downgrade with audit_log), per-package
// rate limiting, and a consecutive-failure circuit breaker.
package versiondiff

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
)

var _ scanner.Scanner = (*VersionDiffScanner)(nil)

const (
	scannerName    = "version-diff"
	scannerVersion = "2.0.0"

	defaultMinConfidence           float32 = 0.6
	defaultPerPackageRateLimit             = 10
	defaultCircuitBreakerThreshold         = 5
	defaultCircuitBreakerCooldown          = 60 * time.Second
	defaultScannerTimeout                  = 55 * time.Second
)

type VersionDiffScanner struct {
	db     *config.GateDB
	cache  cache.CacheStore
	cfg    config.VersionDiffConfig
	client pb.ScannerBridgeClient
	closer func() error

	rateLimiter *packageRateLimiter
	breaker     *consecutiveFailureBreaker
	// flightGroup coalesces concurrent scans of the same (artifact_id, prev_id)
	// pair so a CI burst of 32 parallel requests hits the LLM once, not 32×.
	// The first scan's result is shared with the followers.
	flightGroup singleflight.Group
}

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

	rateN := cfg.PerPackageRateLimit
	if rateN == 0 {
		rateN = defaultPerPackageRateLimit
	}
	bThreshold := cfg.CircuitBreakerThreshold
	if bThreshold == 0 {
		bThreshold = defaultCircuitBreakerThreshold
	}

	s := &VersionDiffScanner{
		db:          db,
		cache:       cs,
		cfg:         cfg,
		client:      client,
		closer:      closer,
		rateLimiter: newPackageRateLimiter(rateN),
		breaker:     newConsecutiveFailureBreaker(bThreshold, defaultCircuitBreakerCooldown),
	}

	return s, nil
}

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

// Scan implements the full AI-driven version-diff flow described in the package doc.
func (s *VersionDiffScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	// 1. Allowlist
	if s.isAllowlisted(artifact.Name) {
		return s.cleanResult(start, nil), nil
	}

	// 2. Compressed-size guard
	maxBytes := int64(s.cfg.MaxArtifactSizeMB) * 1024 * 1024
	if maxBytes > 0 && artifact.SizeBytes > maxBytes {
		log.Debug().Str("artifact", artifact.ID).Int64("size", artifact.SizeBytes).
			Msg("version-diff: skipping large artifact")
		return s.cleanResult(start, nil), nil
	}

	// 3. Sub-timeout
	timeout := defaultScannerTimeout
	if s.cfg.ScannerTimeout != "" {
		if d, err := time.ParseDuration(s.cfg.ScannerTimeout); err == nil && d > 0 {
			timeout = d
		}
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 4. DB query: previous CLEAN/SUSPICIOUS version
	var prevID, prevSHA256, prevVersion string
	err := s.db.QueryRowContext(scanCtx,
		`SELECT a.id, a.sha256, a.version FROM artifacts a
		 JOIN artifact_status s ON a.id = s.artifact_id
		 WHERE a.ecosystem = ? AND a.name = ? AND a.id != ?
		   AND s.status IN ('CLEAN', 'SUSPICIOUS')
		 ORDER BY a.cached_at DESC LIMIT 1`,
		string(artifact.Ecosystem), artifact.Name, artifact.ID,
	).Scan(&prevID, &prevSHA256, &prevVersion)
	if err != nil {
		// No previous version — nothing to diff. Do not insert a row.
		return s.cleanResult(start, nil), nil
	}

	// 5. DB idempotency cache lookup. Use the model name we expect plus an
	//    "any prompt version" wildcard match — we want to hit cache for any
	//    prompt the bridge has used. Most-recent row wins.
	if cached, hit := s.lookupCache(scanCtx, artifact.ID, prevID); hit {
		log.Debug().Str("artifact", artifact.ID).Str("prev", prevID).
			Str("cached_verdict", cached.Verdict).Msg("version-diff: cache hit")
		return s.toResult(start, cached, true), nil
	}

	// 6. cache.Get(prevID) + SHA256 verify
	prevPath, err := s.cache.Get(scanCtx, prevID)
	if err != nil {
		return s.cleanResult(start, fmt.Errorf("cache get previous %s: %w", prevID, err)), nil
	}
	if err := verifySHA256(prevPath, prevSHA256); err != nil {
		return s.cleanResult(start, fmt.Errorf("sha256 mismatch for %s: %w", prevID, err)), nil
	}

	// 7. Per-package rate limit
	if !s.rateLimiter.allow(artifact.Name) {
		log.Debug().Str("package", artifact.Name).Msg("version-diff: rate-limited, returning CLEAN")
		return s.cleanResult(start, nil), nil
	}

	// 8. Circuit breaker
	if !s.breaker.allow(time.Now()) {
		log.Debug().Str("artifact", artifact.ID).Msg("version-diff: circuit open, returning CLEAN")
		return s.cleanResult(start, nil), nil
	}

	// 9. Coalesce concurrent same-pair scans through singleflight, then call
	// the bridge. The first goroutine performs the LLM call; followers receive
	// the same *pb.DiffScanResponse without making their own bridge call.
	flightKey := artifact.ID + "|" + prevID
	respIface, callErr, _ := s.flightGroup.Do(flightKey, func() (any, error) {
		req := &pb.DiffScanRequest{
			ArtifactId:         artifact.ID,
			Ecosystem:          string(artifact.Ecosystem),
			Name:               artifact.Name,
			Version:            artifact.Version,
			PreviousVersion:    prevVersion,
			LocalPath:          artifact.LocalPath,
			PreviousPath:       prevPath,
			OriginalFilename:   artifact.Filename,
			LocalPathSha256:    strings.ToLower(artifact.SHA256),
			PreviousPathSha256: strings.ToLower(prevSHA256),
			PromptVersion:      "", // bridge ignores this — it computes its own SHA from prompt file
		}
		return s.client.ScanArtifactDiff(scanCtx, req)
	})
	if callErr != nil {
		s.breaker.recordFailure(time.Now())
		return s.cleanResult(start, fmt.Errorf("bridge call failed: %w", callErr)), nil
	}
	resp, ok := respIface.(*pb.DiffScanResponse)
	if !ok || resp == nil {
		s.breaker.recordFailure(time.Now())
		return s.cleanResult(start, fmt.Errorf("bridge call: unexpected response type %T", respIface)), nil
	}
	s.breaker.recordSuccess()

	// 10. Verdict mapping
	mapping := s.mapVerdict(resp)

	// Observability: surface successful AI verdicts at INFO level so operators
	// (and e2e tests) can confirm the bridge actually reached the LLM. UNKNOWN
	// stays at the default DEBUG via the fail-open path below.
	if !strings.EqualFold(resp.Verdict, "UNKNOWN") {
		log.Info().
			Str("artifact", artifact.ID).
			Str("prev", prevID).
			Str("ai_verdict", resp.Verdict).
			Float32("ai_confidence", resp.Confidence).
			Str("ai_model", resp.ModelUsed).
			Int32("ai_tokens", resp.TokensUsed).
			Bool("input_truncated", resp.InputTruncated).
			Msg("version-diff: ai scan completed")
	}

	// 11. Persist (skip on UNKNOWN; also skip on SUSPICIOUS→CLEAN downgrade so
	// a future prompt improvement can re-evaluate without being shadowed by
	// a cached "downgraded CLEAN" row).
	persisted := false
	if mapping.persistRow {
		persisted = s.persistRow(scanCtx, artifact, prevID, prevVersion, resp, mapping)
	}

	// 12. Audit log on downgrade. Only record if THIS goroutine was the one
	// that persisted the row (prevents duplicate audit entries when N concurrent
	// scans race; with singleflight only one goroutine reaches here, but we
	// keep the gating for safety against ON CONFLICT no-ops on retries).
	// Special case: low-confidence SUSPICIOUS→CLEAN downgrade is audited even
	// though no row is persisted (mapping.persistRow=false), because the
	// downgrade decision itself is the operationally significant signal.
	if mapping.auditDowngrade && (persisted || !mapping.persistRow) {
		s.writeDowngradeAudit(artifact.ID, mapping.originalVerdict, mapping.finalVerdict, resp.Confidence, mapping.auditReason)
	}

	// 13. Shadow mode override
	finalVerdict := mapping.finalVerdict
	finalFindings := mapping.findings
	if strings.EqualFold(s.cfg.Mode, "shadow") {
		finalVerdict = scanner.VerdictClean
		finalFindings = nil
	}

	return scanner.ScanResult{
		Verdict:        finalVerdict,
		Confidence:     mapping.confidence,
		Findings:       finalFindings,
		ScannerID:      scannerName,
		ScannerVersion: scannerVersion,
		Duration:       time.Since(start),
		ScannedAt:      start,
	}, nil
}

// --- Helpers ---------------------------------------------------------------

type cachedRow struct {
	Verdict     string
	AIVerdict   sql.NullString
	Confidence  sql.NullFloat64
	Explanation sql.NullString
	Model       sql.NullString
}

// lookupCache reads the most-recent persisted row for the (new, prev) pair.
// Cache is intentionally model/prompt-agnostic on read: the bridge may have
// upgraded its prompt or model since the row was written, but the verdict
// recorded then is still operationally valid (we only persist successful LLM
// outcomes; UNKNOWN never reaches the DB). When the operator wants forced
// re-evaluation, they delete rows by `ai_prompt_version` (see docs/scanners/
// version-diff.md). If a stricter "model+prompt match" lookup is required,
// extend this query — but keep equality, not COALESCE, so the unique index
// `uq_version_diff_pair` is usable.
func (s *VersionDiffScanner) lookupCache(ctx context.Context, artifactID, prevID string) (cachedRow, bool) {
	var row cachedRow
	err := s.db.QueryRowContext(ctx,
		`SELECT verdict, ai_verdict, ai_confidence, ai_explanation, ai_model_used
		   FROM version_diff_results
		  WHERE artifact_id = ? AND previous_artifact = ?
		    AND ai_model_used IS NOT NULL    -- v2.0+ rows only (legacy v1.x has NULL)
		  ORDER BY diff_at DESC LIMIT 1`,
		artifactID, prevID,
	).Scan(&row.Verdict, &row.AIVerdict, &row.Confidence, &row.Explanation, &row.Model)
	if err != nil {
		return cachedRow{}, false
	}
	return row, true
}

type verdictMapping struct {
	finalVerdict    scanner.Verdict
	originalVerdict scanner.Verdict
	confidence      float32
	findings        []scanner.Finding
	persistRow      bool
	auditDowngrade  bool
	auditReason     string
}

func (s *VersionDiffScanner) mapVerdict(resp *pb.DiffScanResponse) verdictMapping {
	minConf := s.cfg.MinConfidence
	if minConf == 0 {
		minConf = defaultMinConfidence
	}
	mp := verdictMapping{confidence: resp.Confidence}

	switch strings.ToUpper(resp.Verdict) {
	case "MALICIOUS":
		// Asymmetric downgrade: cross-version diff is structurally weaker than
		// single-version content analysis, so MALICIOUS always becomes SUSPICIOUS
		// regardless of confidence (low-confidence MALICIOUS is still a stronger
		// signal than mid-confidence SUSPICIOUS).
		mp.originalVerdict = scanner.VerdictMalicious
		mp.finalVerdict = scanner.VerdictSuspicious
		mp.persistRow = true
		mp.auditDowngrade = true
		mp.auditReason = "asymmetric-diff-downgrade"
		mp.findings = appendFindings(nil, resp.Findings, scanner.SeverityCritical)
	case "SUSPICIOUS":
		mp.originalVerdict = scanner.VerdictSuspicious
		if resp.Confidence < minConf {
			// Low-confidence downgrade — return CLEAN to caller, write audit row,
			// but DO NOT persist a cache row. A future prompt improvement that
			// would correctly classify this pair MALICIOUS must not be shadowed
			// by a cached "downgraded CLEAN".
			mp.finalVerdict = scanner.VerdictClean
			mp.confidence = 0 // do not surface SUSPICIOUS confidence on a CLEAN result
			mp.persistRow = false
			mp.auditDowngrade = true
			mp.auditReason = "below-min-confidence"
		} else {
			mp.finalVerdict = scanner.VerdictSuspicious
			mp.persistRow = true
			sev := scanner.SeverityHigh
			if resp.Confidence < 0.75 {
				sev = scanner.SeverityMedium
			}
			mp.findings = appendFindings(nil, resp.Findings, sev)
		}
	case "CLEAN":
		mp.originalVerdict = scanner.VerdictClean
		mp.finalVerdict = scanner.VerdictClean
		mp.persistRow = true
	case "UNKNOWN":
		fallthrough
	default:
		// Fail-open: do NOT persist. Idempotency cache must not store UNKNOWN.
		mp.originalVerdict = scanner.VerdictClean
		mp.finalVerdict = scanner.VerdictClean
		mp.persistRow = false
	}
	return mp
}

func appendFindings(out []scanner.Finding, descriptions []string, severity scanner.Severity) []scanner.Finding {
	for _, d := range descriptions {
		out = append(out, scanner.Finding{
			Severity:    severity,
			Category:    "version-diff:ai",
			Description: d,
		})
	}
	if len(out) == 0 {
		out = append(out, scanner.Finding{
			Severity:    severity,
			Category:    "version-diff:ai",
			Description: "AI-detected anomaly in version diff",
		})
	}
	return out
}

// persistRow inserts a verdict row. Returns true if the INSERT actually
// affected a row (i.e. there was no conflict). False on conflict or DB error.
func (s *VersionDiffScanner) persistRow(
	ctx context.Context,
	artifact scanner.Artifact,
	prevID, prevVersion string,
	resp *pb.DiffScanResponse,
	mp verdictMapping,
) bool {
	modelName := resp.ModelUsed
	if modelName == "" {
		modelName = "unknown" // never empty — empty would collide with legacy NULL rows
	}
	prompt := resp.PromptVersion
	if prompt == "" {
		prompt = "unknown" // never empty — same reasoning
	}

	// findings_json is the LLM's structured findings list, JSON-encoded.
	// Empty list when no findings — never silently dropped.
	findingsJSON, mErr := json.Marshal(resp.Findings)
	if mErr != nil {
		findingsJSON = []byte("[]")
	}

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO version_diff_results
		 (artifact_id, previous_artifact, diff_at,
		  files_added, files_modified, files_removed,
		  size_ratio, max_entropy_delta,
		  verdict, findings_json,
		  ai_verdict, ai_confidence, ai_explanation, ai_model_used, ai_prompt_version,
		  ai_tokens_used, previous_version)
		 VALUES (?, ?, ?,
		         ?, ?, ?,
		         NULL, NULL,
		         ?, ?,
		         ?, ?, ?, ?, ?,
		         ?, ?)
		 ON CONFLICT (artifact_id, previous_artifact, ai_model_used, ai_prompt_version) DO NOTHING`,
		artifact.ID, prevID, time.Now().UTC(),
		resp.FilesAdded, resp.FilesModified, resp.FilesRemoved,
		string(mp.finalVerdict),
		string(findingsJSON),
		strings.ToUpper(resp.Verdict), resp.Confidence, truncateUTF8(resp.Explanation, 500),
		modelName, prompt,
		resp.TokensUsed, prevVersion,
	)
	if err != nil {
		log.Warn().Err(err).Str("artifact", artifact.ID).
			Msg("version-diff: failed to persist row (cache write)")
		return false
	}
	rows, _ := res.RowsAffected()
	return rows > 0
}

func (s *VersionDiffScanner) toResult(start time.Time, row cachedRow, fromCache bool) scanner.ScanResult {
	verdict := scanner.Verdict(row.Verdict)
	conf := float32(0)
	if row.Confidence.Valid {
		conf = float32(row.Confidence.Float64)
	}
	res := scanner.ScanResult{
		Verdict:        verdict,
		Confidence:     conf,
		ScannerID:      scannerName,
		ScannerVersion: scannerVersion,
		Duration:       time.Since(start),
		ScannedAt:      start,
	}
	if strings.EqualFold(s.cfg.Mode, "shadow") {
		res.Verdict = scanner.VerdictClean
		res.Findings = nil
	} else if verdict == scanner.VerdictSuspicious && row.Explanation.Valid {
		res.Findings = []scanner.Finding{{
			Severity:    scanner.SeverityHigh,
			Category:    "version-diff:ai",
			Description: row.Explanation.String,
		}}
	}
	return res
}

func (s *VersionDiffScanner) writeDowngradeAudit(artifactID string, original, final scanner.Verdict, confidence float32, reason string) {
	metaBytes, mErr := json.Marshal(struct {
		Scanner           string  `json:"scanner"`
		OriginalVerdict   string  `json:"original_verdict"`
		DowngradedVerdict string  `json:"downgraded_verdict"`
		AIConfidence      float32 `json:"ai_confidence"`
		Reason            string  `json:"reason"`
	}{
		Scanner:           scannerName,
		OriginalVerdict:   string(original),
		DowngradedVerdict: string(final),
		AIConfidence:      confidence,
		Reason:            reason,
	})
	if mErr != nil {
		// Should never happen with these stable types, but if it does, log
		// and skip the entry so we don't write malformed JSON to the audit log.
		log.Warn().Err(mErr).Str("artifact", artifactID).
			Msg("version-diff: failed to marshal downgrade audit metadata")
		return
	}
	if err := adapter.WriteAuditLog(s.db, model.AuditEntry{
		Timestamp:    time.Now().UTC(),
		EventType:    model.EventScannerVerdictDowngraded,
		ArtifactID:   artifactID,
		Reason:       fmt.Sprintf("version-diff: %s → %s (%s)", original, final, reason),
		MetadataJSON: string(metaBytes),
	}); err != nil {
		log.Warn().Err(err).Str("artifact", artifactID).
			Msg("version-diff: failed to write downgrade audit_log entry")
	}
}

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

func (s *VersionDiffScanner) isAllowlisted(name string) bool {
	lower := strings.ToLower(name)
	for _, a := range s.cfg.Allowlist {
		if strings.ToLower(a) == lower {
			return true
		}
	}
	return false
}

// verifySHA256 hashes the file at path and compares to the expected hex string.
// Empty expected = skip verification.
func verifySHA256(path, expected string) error {
	if expected == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", actual, expected)
	}
	return nil
}

// truncateUTF8 returns the longest prefix of s that fits in maxBytes bytes
// without splitting a UTF-8 codepoint. Use this when persisting LLM output
// that may contain multi-byte characters — naive `s[:maxBytes]` could write
// invalid UTF-8 and corrupt downstream JSON parsers.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Find the largest valid UTF-8 boundary <= maxBytes.
	end := maxBytes
	for end > 0 {
		_, size := utf8.DecodeLastRuneInString(s[:end])
		if size > 0 && utf8.ValidString(s[:end]) {
			break
		}
		end--
	}
	return s[:end]
}
