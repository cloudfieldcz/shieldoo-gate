# Version-Diff AI Rebuild — Phase 6a: Go scanner skeleton + config

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay down the Go-side skeleton: delete the legacy heuristic files, replace `VersionDiffScanner` with a gRPC-client struct that returns CLEAN as a stub, swap in the new `VersionDiffConfig`, redo `validateVersionDiff`, add `defer Close()` for both AI and version-diff scanners. No real Scan logic yet — Phase 6b plugs in the bridge call.

**Architecture:** Mirror [internal/scanner/ai/scanner.go](../../internal/scanner/ai/scanner.go): a struct holding a `pb.ScannerBridgeClient`, a `closer func() error`, and `cfg config.VersionDiffConfig`. The dial helper is reused from [internal/scanner/ai/client.go](../../internal/scanner/ai/client.go) (we expose it as a package-level helper or copy the four-line dial code).

**Tech Stack:** Go 1.25, `google.golang.org/grpc`, `github.com/jmoiron/sqlx` via `*config.GateDB`.

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

- Old files to delete: [internal/scanner/versiondiff/diff.go](../../internal/scanner/versiondiff/diff.go) (547 lines) and [internal/scanner/versiondiff/extractor.go](../../internal/scanner/versiondiff/extractor.go) (295 lines). Both are heuristic Go code that the rebuild replaces with the Python bridge.
- Existing test file [internal/scanner/versiondiff/scanner_test.go](../../internal/scanner/versiondiff/scanner_test.go) (614 lines) is bound to the old logic. Phase 6c rewrites it. For Phase 6a we delete the test contents (or comment-skip them) so `make test` is green while we land the skeleton.
- The dial helper in [internal/scanner/ai/client.go](../../internal/scanner/ai/client.go) is package-private. We add a sibling `internal/scanner/versiondiff/client.go` with the same minimal dialer to avoid creating a cross-package dependency. Both files are 24-line trivial wrappers — duplication is intentional per CLAUDE.md "three similar lines is better than premature abstraction".
- The `Close` method on `*VersionDiffScanner` and `*AIScanner` must be invoked at shutdown. The current main.go does NOT call `defer ai.Close()` — Phase 6a fixes both.
- The new config field set is described in the analysis at [version-diff-ai-rebuild.md:553-571](./2026-04-30-version-diff-ai-rebuild.md#L553).

---

### Task 1: Delete legacy heuristic files

**Files:**
- Delete: `internal/scanner/versiondiff/diff.go`
- Delete: `internal/scanner/versiondiff/extractor.go`

- [ ] **Step 1: Delete the two files**

```bash
rm internal/scanner/versiondiff/diff.go internal/scanner/versiondiff/extractor.go
```

- [ ] **Step 2: Verify the build now fails (expected — `scanner.go` references symbols from those files)**

```bash
go build ./internal/scanner/versiondiff/
```

Expected: errors about undefined `RunDiff`, `ExtractArchive`, `DiffResult`, `ExtractLimits`, `scoreFindings`, etc. We'll fix these in the next tasks.

(No commit yet — combined with the rewrite.)

---

### Task 2: Rewrite `internal/config/config.go` `VersionDiffConfig` + `validateVersionDiff`

**Files:**
- Modify: [internal/config/config.go:290-308](../../internal/config/config.go#L290-L308) (struct)
- Modify: [internal/config/config.go:303-308](../../internal/config/config.go#L303-L308) (the `VersionDiffThresholds` struct, delete it)
- Modify: [internal/config/config.go:852-871](../../internal/config/config.go#L852-L871) (validator)

- [ ] **Step 1: Replace the struct definition**

In [internal/config/config.go:290-308](../../internal/config/config.go#L290-L308), replace both `VersionDiffConfig` and `VersionDiffThresholds`:

```go
// VersionDiffConfig holds configuration for the AI-driven version diff scanner.
// The scanner sends new + previous artifact paths to scanner-bridge over gRPC,
// where a Python module extracts diffs and calls the LLM (gpt-5.4-mini default).
//
// Mode "shadow" runs the scanner but ScanResult.Verdict is forced to CLEAN so
// the policy engine ignores it. Mode "active" passes the LLM verdict through.
type VersionDiffConfig struct {
	Enabled                 bool     `mapstructure:"enabled"`
	Mode                    string   `mapstructure:"mode"`                       // "shadow" | "active"
	MaxArtifactSizeMB       int      `mapstructure:"max_artifact_size_mb"`       // default 50
	MaxExtractedSizeMB      int      `mapstructure:"max_extracted_size_mb"`      // default 50
	MaxExtractedFiles       int      `mapstructure:"max_extracted_files"`        // default 5000
	ScannerTimeout          string   `mapstructure:"scanner_timeout"`            // default "55s" — must be < scanners.timeout
	BridgeSocket            string   `mapstructure:"bridge_socket"`              // shared with ai-scanner; empty = reuse guarddog socket
	Allowlist               []string `mapstructure:"allowlist"`
	MinConfidence           float32  `mapstructure:"min_confidence"`             // default 0.6 — SUSPICIOUS below this is downgraded to CLEAN with audit_log entry
	PerPackageRateLimit     int      `mapstructure:"per_package_rate_limit"`     // default 10 LLM calls/h/package; 0 = unlimited
	DailyCostLimitUSD       float64  `mapstructure:"daily_cost_limit_usd"`       // default 5.0; circuit breaker auto-disables on exceed
	CircuitBreakerThreshold int      `mapstructure:"circuit_breaker_threshold"`  // default 5 consecutive failures triggers 60 s pause
}
```

Remove the `VersionDiffThresholds` struct entirely (it's no longer referenced).

- [ ] **Step 2: Replace `validateVersionDiff`**

In [internal/config/config.go:852-871](../../internal/config/config.go#L852-L871), replace the function body:

```go
func (c *Config) validateVersionDiff() error {
	vc := c.Scanners.VersionDiff
	if !vc.Enabled {
		return nil
	}
	if vc.Mode != "" && vc.Mode != "shadow" && vc.Mode != "active" {
		return fmt.Errorf("config: scanners.version_diff.mode must be 'shadow' or 'active', got %q", vc.Mode)
	}
	if vc.MaxArtifactSizeMB < 1 {
		return fmt.Errorf("config: scanners.version_diff.max_artifact_size_mb must be >= 1, got %d", vc.MaxArtifactSizeMB)
	}
	if vc.MaxExtractedSizeMB < 1 {
		return fmt.Errorf("config: scanners.version_diff.max_extracted_size_mb must be >= 1, got %d", vc.MaxExtractedSizeMB)
	}
	if vc.MaxExtractedFiles < 100 {
		return fmt.Errorf("config: scanners.version_diff.max_extracted_files must be >= 100, got %d", vc.MaxExtractedFiles)
	}
	if vc.ScannerTimeout != "" {
		if _, err := time.ParseDuration(vc.ScannerTimeout); err != nil {
			return fmt.Errorf("config: scanners.version_diff.scanner_timeout %q is not a valid duration: %w", vc.ScannerTimeout, err)
		}
	}
	if vc.MinConfidence < 0 || vc.MinConfidence > 1 {
		return fmt.Errorf("config: scanners.version_diff.min_confidence must be in [0,1], got %f", vc.MinConfidence)
	}
	if vc.PerPackageRateLimit < 0 {
		return fmt.Errorf("config: scanners.version_diff.per_package_rate_limit must be >= 0, got %d", vc.PerPackageRateLimit)
	}
	if vc.DailyCostLimitUSD < 0 {
		return fmt.Errorf("config: scanners.version_diff.daily_cost_limit_usd must be >= 0, got %f", vc.DailyCostLimitUSD)
	}
	if vc.CircuitBreakerThreshold < 0 {
		return fmt.Errorf("config: scanners.version_diff.circuit_breaker_threshold must be >= 0, got %d", vc.CircuitBreakerThreshold)
	}
	// bridge_socket is intentionally NOT validated here: an empty value is
	// allowed at config-load time and inherits scanners.guarddog.bridge_socket
	// in cmd/shieldoo-gate/main.go before NewVersionDiffScanner runs. The
	// constructor enforces non-empty.
	return nil
}
```

- [ ] **Step 3: Make sure the `time` package is already imported**

```bash
grep "\"time\"" internal/config/config.go | head -1
```

Expected: present. If not, add it.

- [ ] **Step 4: Build**

```bash
go build ./internal/config/...
```

Expected: success.

(No commit yet — config is needed by the scanner skeleton.)

---

### Task 3: Add the dial helper `internal/scanner/versiondiff/client.go`

**Files:**
- Create: `internal/scanner/versiondiff/client.go`

- [ ] **Step 1: Write the dialer**

Create [internal/scanner/versiondiff/client.go](../../internal/scanner/versiondiff/client.go):

```go
package versiondiff

import (
	"fmt"

	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// dialBridge connects to the scanner-bridge gRPC server over a Unix socket.
// Returns the client, a closer function, and any error. Mirrors the helper in
// internal/scanner/ai/client.go — duplicated rather than imported to avoid a
// cross-package dependency for a four-line wrapper.
func dialBridge(socketPath string) (pb.ScannerBridgeClient, func() error, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("version-diff scanner: dialing bridge at %s: %w", socketPath, err)
	}
	return pb.NewScannerBridgeClient(conn), conn.Close, nil
}
```

- [ ] **Step 2: Build**

```bash
go build ./internal/scanner/versiondiff/...
```

Expected: still errors from `scanner.go` (rewritten in Task 4).

---

### Task 4: Replace `internal/scanner/versiondiff/scanner.go` with the skeleton

**Files:**
- Modify: [internal/scanner/versiondiff/scanner.go](../../internal/scanner/versiondiff/scanner.go) (full rewrite)

- [ ] **Step 1: Replace the file**

Rewrite [internal/scanner/versiondiff/scanner.go](../../internal/scanner/versiondiff/scanner.go) with the skeleton (no Scan flow yet):

```go
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
```

- [ ] **Step 2: Build**

```bash
go build ./internal/scanner/versiondiff/...
```

Expected: success.

- [ ] **Step 3: Stub out the existing test file (Phase 6c will rewrite it properly)**

The legacy test file references symbols (`RunDiff`, `DiffResult`, `scoreFindings`, etc.) that no longer exist. Replace it with a minimal placeholder so `go test` is green.

Replace [internal/scanner/versiondiff/scanner_test.go](../../internal/scanner/versiondiff/scanner_test.go) entirely with:

```go
package versiondiff

// Tests for the AI-driven scanner are added in Phase 6c (post-Scan-flow).
// This package compiles in Phase 6a so the rest of the build is unblocked.
```

- [ ] **Step 4: Run tests**

```bash
go build ./...
go test ./internal/scanner/versiondiff/ -v
```

Expected: build succeeds; package has no tests yet (`ok ... [no test files]` is acceptable, or `0 tests run`).

(No commit yet — combined with main.go in Task 5.)

---

### Task 5: Wire `defer Close()` in `cmd/shieldoo-gate/main.go`

**Files:**
- Modify: [cmd/shieldoo-gate/main.go:205-211](../../cmd/shieldoo-gate/main.go#L205-L211) (AI scanner registration)
- Modify: [cmd/shieldoo-gate/main.go:237-245](../../cmd/shieldoo-gate/main.go#L237-L245) (version-diff scanner registration)

- [ ] **Step 1: Add `defer ai.Close()` after AI scanner init**

In [cmd/shieldoo-gate/main.go:205-211](../../cmd/shieldoo-gate/main.go#L205-L211), the current code is:

```go
		ai, err := aiscanner.NewAIScanner(aiCfg)
		if err != nil {
			log.Warn().Err(err).Msg("ai scanner disabled: failed to init")
		} else {
			scanners = append(scanners, ai)
			log.Info().Str("model", cfg.Scanners.AI.Model).Str("provider", cfg.Scanners.AI.Provider).Msg("ai scanner enabled")
		}
```

Change to:

```go
		ai, err := aiscanner.NewAIScanner(aiCfg)
		if err != nil {
			log.Warn().Err(err).Msg("ai scanner disabled: failed to init")
		} else {
			scanners = append(scanners, ai)
			defer func() {
				if err := ai.Close(); err != nil {
					log.Warn().Err(err).Msg("ai scanner: close failed")
				}
			}()
			log.Info().Str("model", cfg.Scanners.AI.Model).Str("provider", cfg.Scanners.AI.Provider).Msg("ai scanner enabled")
		}
```

- [ ] **Step 2: Add `defer vd.Close()` after version-diff init**

In [cmd/shieldoo-gate/main.go:237-245](../../cmd/shieldoo-gate/main.go#L237-L245):

```go
	if cfg.Scanners.VersionDiff.Enabled {
		vd, err := versiondiff.NewVersionDiffScanner(db, cacheStore, cfg.Scanners.VersionDiff)
		if err != nil {
			log.Warn().Err(err).Msg("version-diff scanner disabled: failed to init")
		} else {
			scanners = append(scanners, vd)
			defer func() {
				if err := vd.Close(); err != nil {
					log.Warn().Err(err).Msg("version-diff scanner: close failed")
				}
			}()
			log.Info().Msg("version-diff scanner enabled")
		}
	}
```

- [ ] **Step 3: Verify the bridge socket fallback for version-diff**

In `main.go`, the AI scanner has a fallback at line 202-204:

```go
		if aiCfg.Socket == "" {
			aiCfg.Socket = cfg.Scanners.GuardDog.BridgeSocket // reuse same bridge socket
		}
```

Add an analogous fallback for the VersionDiff config before the `NewVersionDiffScanner` call:

```go
	if cfg.Scanners.VersionDiff.Enabled {
		if cfg.Scanners.VersionDiff.BridgeSocket == "" {
			cfg.Scanners.VersionDiff.BridgeSocket = cfg.Scanners.GuardDog.BridgeSocket // reuse same bridge socket
		}
		vd, err := versiondiff.NewVersionDiffScanner(db, cacheStore, cfg.Scanners.VersionDiff)
		// ... (rest as in Step 2)
```

The `validateVersionDiff` validator (Task 2) requires `BridgeSocket != ""`. With this main.go fallback, an empty `version_diff.bridge_socket` in YAML inherits guarddog's socket BEFORE validation runs (validation re-runs after the assignment isn't necessary — we set the field on the in-memory `cfg` struct, then construct).

> **Note:** the `validate` step in `internal/config` runs at config-load time, **before** main.go applies the fallback. To avoid a "bridge_socket is required when scanner is enabled" startup failure for users who only configure guarddog's socket, the validator must accept empty bridge_socket and rely on main.go's fallback. **Update `validateVersionDiff` in Task 2 Step 2** by removing the standalone bridge_socket-empty check, OR add a cross-reference check that allows empty IF `cfg.Scanners.GuardDog.BridgeSocket != ""`. The simpler fix is to drop the validator check; the constructor `NewVersionDiffScanner` still rejects empty after main.go's fallback. Apply this in Phase 6a (this phase) — replace the `if vc.BridgeSocket == ""` check in `validateVersionDiff` with nothing, and rely on main.go to set it before `NewVersionDiffScanner`.

- [ ] **Step 4: Build + lint**

```bash
make build
make lint
```

Expected: success on both.

- [ ] **Step 5: Run the full test suite**

```bash
make test
```

Expected: all tests pass. The empty `versiondiff` package adds no tests; nothing else should regress.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go \
        internal/scanner/versiondiff/scanner.go \
        internal/scanner/versiondiff/scanner_test.go \
        internal/scanner/versiondiff/client.go \
        cmd/shieldoo-gate/main.go
# diff.go and extractor.go were rm'd in Task 1 — git add notices the deletions:
git add -u internal/scanner/versiondiff/
git commit -m "refactor(version-diff): drop heuristic, replace with gRPC-client skeleton + new config schema"
```

---

## Verification — phase-end

```bash
# Build + lint clean
make build && make lint

# Test suite green
make test

# Old heuristic files are gone
[ ! -f internal/scanner/versiondiff/diff.go ] && [ ! -f internal/scanner/versiondiff/extractor.go ] && echo "ok: legacy files removed"

# No leftover references to deprecated symbols
grep -rn "RunDiff\|builtinSensitivePatterns\|EntropySampleBytes\|VersionDiffThresholds\|scoreFindings" \
    internal/ cmd/ 2>/dev/null && echo "FAIL: leftover symbol" || echo "ok: no leftover refs"

# Scanner can be constructed (smoke at startup will succeed when bridge is up)
grep -A1 "NewVersionDiffScanner" cmd/shieldoo-gate/main.go | head -5
```

## What this phase ships

- Two legacy files removed.
- A new `VersionDiffScanner` skeleton struct with gRPC client, `Close()` lifecycle, and Stub-CLEAN `Scan()`.
- `VersionDiffConfig` rewritten with the new fields (mode, min_confidence, rate limit, cost cap, circuit breaker threshold). Old `Thresholds`/`SensitivePatterns`/`EntropySampleBytes` removed.
- `validateVersionDiff` updated to validate the new fields.
- Both `ai-scanner` and `version-diff` get `defer Close()` in `main.go`.

## What this phase deliberately does NOT ship

- No real Scan logic (Phase 6b).
- No tests (Phase 6c).
- No config example update — Phase 7 reshapes `config.example.yaml`.
- No ADR — Phase 7.

## Risks during this phase

- **Stub Scan returns CLEAN.** Until Phase 6b lands, the scanner does nothing useful. The `mode: shadow` config in Phase 7 would be a no-op. **Do not enable the scanner in production between 6a and 6b** (the build doesn't break, but the scanner produces zero signal).
- **Backwards-compatible config keys.** The old config in production has `thresholds:`, `entropy_sample_bytes:`, `sensitive_patterns:` — Viper/mapstructure silently ignores unknown keys. The validator does NOT reject them, so existing configs continue to load. The keys become dead but cause no startup failure.
- **`Close()` already existed on AIScanner** ([internal/scanner/ai/scanner.go:54](../../internal/scanner/ai/scanner.go#L54)) but main.go never called it. Phase 6a fixes that — minor lifecycle improvement, no behavioral change in steady state.
- **The dialer never returns a "bridge is unreachable" error here.** `grpc.NewClient` is lazy — it only validates the URL syntax. Real reachability is verified by `HealthCheck` or by the first RPC call. Phase 6b's flow handles unreachability via fail-open.
