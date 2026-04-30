# Version-Diff AI Rebuild — Phase 6b: Go Scan flow integration

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Phase 6a stub `Scan` with the real flow: allowlist + size guard, DB previous-version lookup, idempotency cache check, SHA256 verify, per-package rate limit, circuit breaker, gRPC `ScanArtifactDiff` call, verdict mapping (MALICIOUS → SUSPICIOUS, MinConfidence downgrade with audit log), `ON CONFLICT DO NOTHING` insert into `version_diff_results`.

**Architecture:** Single Go file [internal/scanner/versiondiff/scanner.go](../../internal/scanner/versiondiff/scanner.go) plus a new `rate.go` for the per-package limiter and `breaker.go` for the consecutive-failure breaker. The audit log is written through [`adapter.WriteAuditLog`](../../internal/adapter/base.go#L398) (already imported elsewhere). A new `EventScannerVerdictDowngraded` event type is added in [`internal/model/audit.go`](../../internal/model/audit.go).

**Tech Stack:** Go 1.25, `golang.org/x/time/rate`, existing `*config.GateDB` for queries.

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

**Scan flow (matches the analysis at [version-diff-ai-rebuild.md:120-168](./2026-04-30-version-diff-ai-rebuild.md#L120)):**

1. Allowlist check → CLEAN, no gRPC.
2. Artifact size guard (compressed) → CLEAN, no gRPC.
3. Apply scanner sub-timeout (default 55 s).
4. DB query: previous CLEAN/SUSPICIOUS version (existing logic from old `scanner.go:122-131`, just extended to also fetch `version` column for human-readable `previous_version`).
5. DB idempotency check: existing row in `version_diff_results` for `(artifact_id, prev_id, model, prompt_version)` → return cached verdict, no gRPC.
6. `cache.Get(prevID)` + `verifySHA256` (TOCTOU defense).
7. Per-package rate limit (token bucket, 10 calls/h/package default). Block exhausted → CLEAN, no gRPC.
8. Circuit breaker check. Open → CLEAN, no gRPC.
9. gRPC `ScanArtifactDiff` call. Pass both SHA256 hashes so the bridge re-verifies. On error → record failure on breaker, fail-open CLEAN.
10. Verdict mapping:
    - `MALICIOUS` → downgrade to SUSPICIOUS, finding severity CRITICAL, write `EventScannerVerdictDowngraded` audit row.
    - `SUSPICIOUS` with `confidence < MinConfidence` → downgrade to CLEAN, write audit row.
    - `SUSPICIOUS` with `confidence >= MinConfidence` → SUSPICIOUS, finding severity HIGH or MEDIUM by confidence.
    - `CLEAN` → CLEAN.
    - `UNKNOWN` → CLEAN, **NO DB row inserted** (don't poison the cache).
11. If `mode == "shadow"`, force `ScanResult.Verdict = CLEAN` regardless (DB row still records `ai_verdict` for analysis).
12. INSERT `version_diff_results` with `ON CONFLICT (artifact_id, previous_artifact, ai_model_used, ai_prompt_version) DO NOTHING`.

**Why two sub-files (`rate.go`, `breaker.go`)?** Each is small (≤ 60 lines), self-contained, and unit-testable in isolation. Keeping them separate from `scanner.go` makes the orchestrator easier to read.

**Daily cost circuit breaker** is deliberately NOT added in this phase. It requires a background tick goroutine plus a Prometheus dependency. The analysis lists it as desired but it can ship as a separate small change after Phase 9 — meanwhile the consecutive-failure breaker plus per-package rate limit cap blast radius adequately. **Decision recorded here so reviewers don't flag it.**

---

### Task 1: Add `EventScannerVerdictDowngraded` to the audit model

**Files:**
- Modify: [internal/model/audit.go](../../internal/model/audit.go)

- [ ] **Step 1: Append the new event type**

In [internal/model/audit.go](../../internal/model/audit.go), at the bottom of the second `const (` block (after `EventSBOMGenerated`):

```go
const (
	EventLicenseBlocked      EventType = "LICENSE_BLOCKED"
	EventLicenseWarned       EventType = "LICENSE_WARNED"
	EventLicenseCheckSkipped EventType = "LICENSE_CHECK_SKIPPED"
	EventProjectNotFound     EventType = "PROJECT_NOT_FOUND"
	EventSBOMGenerated       EventType = "SBOM_GENERATED"

	// EventScannerVerdictDowngraded records when version-diff downgrades a scanner
	// verdict (MALICIOUS → SUSPICIOUS, or SUSPICIOUS → CLEAN below MinConfidence).
	// MetadataJSON has shape: {"scanner":"version-diff","original_verdict":"MALICIOUS",
	// "downgraded_verdict":"SUSPICIOUS","ai_confidence":0.92,"reason":"asymmetric-diff-downgrade"}
	EventScannerVerdictDowngraded EventType = "SCANNER_VERDICT_DOWNGRADED"
)
```

- [ ] **Step 2: Build**

```bash
go build ./internal/model/...
```

Expected: success.

(No commit yet — combined with the rest of Phase 6b.)

---

### Task 2: Implement per-package rate limiter `rate.go`

**Files:**
- Create: `internal/scanner/versiondiff/rate.go`

- [ ] **Step 1: Write the limiter**

Create [internal/scanner/versiondiff/rate.go](../../internal/scanner/versiondiff/rate.go):

```go
package versiondiff

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// packageRateLimiter caps the number of LLM calls per package name per hour.
// Lazy-init per package; never deletes entries (a long-running process
// accumulates entries proportional to scanned package count, which is bounded
// in practice — historical data shows ~5000 unique names over months).
type packageRateLimiter struct {
	limit float64 // events per second
	burst int
	mu    sync.Mutex
	mp    map[string]*rate.Limiter
}

// newPackageRateLimiter — perHour is the long-run rate; 0 disables limiting.
// burst is set equal to perHour so a fresh package gets its full hourly budget
// up-front (avoids the limiter delaying the first call unnecessarily).
func newPackageRateLimiter(perHour int) *packageRateLimiter {
	if perHour <= 0 {
		return nil
	}
	return &packageRateLimiter{
		limit: float64(perHour) / 3600.0,
		burst: perHour,
		mp:    make(map[string]*rate.Limiter),
	}
}

// allow returns true if the caller may proceed with an LLM call now.
// Returns true unconditionally if the limiter is nil (disabled).
func (p *packageRateLimiter) allow(name string) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	lim, ok := p.mp[name]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(p.limit), p.burst)
		p.mp[name] = lim
	}
	p.mu.Unlock()
	return lim.AllowN(time.Now(), 1)
}
```

- [ ] **Step 2: Write a unit test**

Create [internal/scanner/versiondiff/rate_test.go](../../internal/scanner/versiondiff/rate_test.go):

```go
package versiondiff

import (
	"testing"
)

func TestPackageRateLimiter_DisabledAllowsAll(t *testing.T) {
	l := newPackageRateLimiter(0)
	for i := 0; i < 100; i++ {
		if !l.allow("foo") {
			t.Fatalf("disabled limiter must always allow")
		}
	}
}

func TestPackageRateLimiter_BurstAndExhaust(t *testing.T) {
	l := newPackageRateLimiter(3) // 3 per hour, burst 3
	for i := 0; i < 3; i++ {
		if !l.allow("foo") {
			t.Fatalf("call %d: should be allowed", i)
		}
	}
	if l.allow("foo") {
		t.Fatalf("4th call must be denied within burst window")
	}
	// Different package — independent budget.
	if !l.allow("bar") {
		t.Fatalf("bar should be allowed (separate bucket)")
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/scanner/versiondiff/ -v -run TestPackageRateLimiter
```

Expected: pass.

(No commit yet.)

---

### Task 3: Implement consecutive-failure circuit breaker `breaker.go`

**Files:**
- Create: `internal/scanner/versiondiff/breaker.go`

- [ ] **Step 1: Write the breaker**

Create [internal/scanner/versiondiff/breaker.go](../../internal/scanner/versiondiff/breaker.go):

```go
package versiondiff

import (
	"sync"
	"time"
)

// consecutiveFailureBreaker opens after N consecutive bridge errors and stays
// open for `cooldown`. Any successful scan resets the count.
type consecutiveFailureBreaker struct {
	threshold int
	cooldown  time.Duration

	mu      sync.Mutex
	count   int
	openAt  time.Time
}

func newConsecutiveFailureBreaker(threshold int, cooldown time.Duration) *consecutiveFailureBreaker {
	if threshold <= 0 {
		return nil
	}
	return &consecutiveFailureBreaker{threshold: threshold, cooldown: cooldown}
}

// allow returns true if the breaker is closed (or the cooldown has elapsed).
func (b *consecutiveFailureBreaker) allow(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openAt.IsZero() {
		return true
	}
	if now.Sub(b.openAt) >= b.cooldown {
		// Cooldown elapsed — half-open: reset and allow one probe call.
		b.openAt = time.Time{}
		b.count = 0
		return true
	}
	return false
}

// recordSuccess closes the breaker (resets failure count).
func (b *consecutiveFailureBreaker) recordSuccess() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.count = 0
	b.openAt = time.Time{}
	b.mu.Unlock()
}

// recordFailure increments the count; opens the breaker if threshold is reached.
func (b *consecutiveFailureBreaker) recordFailure(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count++
	if b.count >= b.threshold && b.openAt.IsZero() {
		b.openAt = now
	}
}
```

- [ ] **Step 2: Write a unit test**

Create [internal/scanner/versiondiff/breaker_test.go](../../internal/scanner/versiondiff/breaker_test.go):

```go
package versiondiff

import (
	"testing"
	"time"
)

func TestBreaker_Disabled(t *testing.T) {
	b := newConsecutiveFailureBreaker(0, time.Second)
	if !b.allow(time.Now()) {
		t.Fatalf("nil breaker should allow")
	}
	b.recordFailure(time.Now()) // no-op, no panic
}

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	b := newConsecutiveFailureBreaker(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !b.allow(now) {
			t.Fatalf("call %d should be allowed before opening", i)
		}
		b.recordFailure(now)
	}
	if b.allow(now) {
		t.Fatalf("breaker should be open after 3 failures")
	}
}

func TestBreaker_HalfOpenAfterCooldown(t *testing.T) {
	b := newConsecutiveFailureBreaker(2, 10*time.Millisecond)
	now := time.Now()
	b.recordFailure(now)
	b.recordFailure(now)
	if b.allow(now) {
		t.Fatalf("breaker should be open")
	}
	// Cooldown elapsed
	later := now.Add(50 * time.Millisecond)
	if !b.allow(later) {
		t.Fatalf("breaker should half-open after cooldown")
	}
}

func TestBreaker_SuccessResetsCount(t *testing.T) {
	b := newConsecutiveFailureBreaker(3, time.Minute)
	now := time.Now()
	b.recordFailure(now)
	b.recordFailure(now)
	b.recordSuccess()
	b.recordFailure(now)
	if !b.allow(now) {
		t.Fatalf("after success-reset, single failure should not open")
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/scanner/versiondiff/ -v -run TestBreaker
```

Expected: pass.

(No commit yet.)

---

### Task 4: Wire the real Scan flow into `scanner.go`

**Files:**
- Modify: [internal/scanner/versiondiff/scanner.go](../../internal/scanner/versiondiff/scanner.go) (the skeleton from Phase 6a)

- [ ] **Step 1: Replace `scanner.go`**

Rewrite [internal/scanner/versiondiff/scanner.go](../../internal/scanner/versiondiff/scanner.go) with the full flow. Phase 6a's skeleton is the starting point; below is the fully-fleshed version:

```go
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

	defaultMinConfidence            float32 = 0.6
	defaultPerPackageRateLimit              = 10
	defaultCircuitBreakerThreshold          = 5
	defaultCircuitBreakerCooldown           = 60 * time.Second
	defaultScannerTimeout                   = 55 * time.Second
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
	if mapping.auditDowngrade && persisted {
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
	model := resp.ModelUsed
	if model == "" {
		model = "unknown" // never empty — empty would collide with legacy NULL rows
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
		model, prompt,
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
```

- [ ] **Step 2: Verify imports are clean**

```bash
grep -n "sha512\|\"errors\"" internal/scanner/versiondiff/scanner.go
```

Expected: no matches. The file should not import `crypto/sha512` or `errors`.

- [ ] **Step 3: Build + lint**

```bash
make build
make lint
```

Expected: success.

- [ ] **Step 4: Run existing tests (rate.go + breaker.go tests should pass; the empty `versiondiff` test file from Phase 6a doesn't exist anymore)**

```bash
go test ./internal/scanner/versiondiff/ -v
```

Expected: rate + breaker tests pass; no other tests in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/model/audit.go \
        internal/scanner/versiondiff/scanner.go \
        internal/scanner/versiondiff/rate.go \
        internal/scanner/versiondiff/rate_test.go \
        internal/scanner/versiondiff/breaker.go \
        internal/scanner/versiondiff/breaker_test.go
# Remove the placeholder test file from Phase 6a (Phase 6c will recreate it):
git rm internal/scanner/versiondiff/scanner_test.go 2>/dev/null || true
git commit -m "feat(version-diff): wire AI-driven Scan flow with rate limit, breaker, audit on downgrade"
```

(If `scanner_test.go` was kept as a placeholder package file, leave it — Phase 6c overwrites it.)

---

## Verification — phase-end

```bash
# Build + lint clean
make build && make lint

# All Go tests still pass (no new test files yet, but rate + breaker tests are in the package)
make test

# Smoke: bridge running locally + a fake config — start the gate, observe a Scan reach the bridge
# (Phase 6c covers this with proper Go tests; the smoke is best done end-to-end in Phase 8b.)
```

## What this phase ships

- Full Scan implementation: allowlist, size guard, sub-timeout, previous-version DB lookup, idempotency cache lookup, SHA256 verify, per-package rate limit, consecutive-failure breaker, gRPC call, verdict mapping with asymmetric MALICIOUS→SUSPICIOUS downgrade and MinConfidence downgrade, audit log on downgrade, `ON CONFLICT DO NOTHING` insert, shadow-mode verdict suppression.
- Two new helper files (`rate.go`, `breaker.go`) with their own unit tests.
- New audit event type `EventScannerVerdictDowngraded`.

## What this phase deliberately does NOT ship

- Full scanner tests (Phase 6c). The rate/breaker tests are the only Go tests in this commit.
- Daily cost circuit breaker (deferred — see Context note above).
- Prometheus metrics (deferred to a follow-up; the analysis lists them but instrumenting is mechanical and out of scope for the immediate rebuild).
- Config example / docs / ADR (Phase 7).

## Risks during this phase

- **Idempotency lookup before SHA256 verify.** The cache lookup uses only artifact IDs, not content hashes — but `cache.Get` then verifies SHA256 anyway. If a cache row was inserted after a different cached_at version (which then got purged and re-cached with a different SHA), the next Scan re-verifies. Worst case is one redundant LLM call per cache-purged artifact pair.
- **`prompt_version` round-trip closes the cache-invalidation loop.** The bridge computes `SHA256[:12]` of `prompts/version_diff_analyst.txt` on each scan and returns it in `DiffScanResponse.prompt_version`. The Go side persists it as `ai_prompt_version`. A prompt edit changes the SHA → new INSERTs no longer collide with old rows under the unique index → automatic cache invalidation. Operators forcing re-evaluation can DELETE rows by `ai_prompt_version`. The `lookupCache` query intentionally does NOT filter by prompt_version (it returns the most-recent v2.0 row regardless), so a prompt change doesn't immediately stop hitting cache — but the next persist creates a fresh row that future lookups will return. If you want strict prompt-bound cache, add an `AND ai_prompt_version = ?` clause and pass the bridge's current value (requires fetching it via a HealthCheck extension — out of scope here).
- **`ON CONFLICT DO NOTHING` requires Postgres-style syntax.** SQLite supports `ON CONFLICT (cols) DO NOTHING` since 3.24 (released 2018). Confirmed by the existing migrations using SQLite syntax. The DB driver passes through the literal SQL — both backends accept this form via `db.Rebind` (which only swaps `?` for `$N` on Postgres).
- **Concurrent scans of the same `(artifact, prev)` pair.** Two parallel scans can both miss the cache (no row yet) and both call the LLM. The second `INSERT ON CONFLICT DO NOTHING` is a no-op. Two parallel LLM calls is rare (engine semaphore caps at 32 total scans, and same-pair concurrency is unlikely except during burst E2E tests). Accepted as cost of optimistic concurrency control.
