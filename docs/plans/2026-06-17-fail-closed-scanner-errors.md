# Fail-Closed Scanner Errors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Required inline scanners that fail, time out, overload, or return UNKNOWN must not let unscanned artifacts become servable.

**Architecture:** Add explicit scanner completeness reporting at the scan engine, let policy map required scanner failures to `retry_later`, `block`, or explicit `fail_open`, and let adapters map `retry_later` to pull/push/sync semantics. Keep the error path stateless: no new artifact status, no staging area, no background retry.

**Tech Stack:** Go, existing `scanner`, `policy`, `adapter`, `config`, `model`, Prometheus client, React audit log UI, OpenAPI YAML.

---

## Source Spec

Implement the approved design in `docs/specs/2026-06-17-fail-closed-scanner-errors-design.md`.

## Guardrails

- Do not add a new artifact status.
- Do not persist fetched bytes, cache entries, tags, or clean `artifact_status` rows on scanner-unavailable paths.
- Do not add per-project overrides for scanner failure mode.
- Do not introduce a scheduler or background retry.
- Keep `scanner.NewEngine(...)` source-compatible by adding variadic options.
- Keep `policy.Engine.Evaluate(...)` as a compatibility wrapper and add `EvaluateReport(...)` for the new behavior.
- Add one shared pull-response helper in `internal/adapter/base.go`; do not duplicate 503 response code in every ecosystem.
- Add focused adapter integration coverage for PyPI pull, Docker push, and Docker sync, plus policy/scanner unit tests for the shared behavior.

## File Structure

- Create `internal/scanner/errors.go`: scanner error taxonomy, gRPC/status mapping, and classification helper.
- Create `internal/scanner/metrics.go`: scanner error and circuit-breaker metrics.
- Modify `internal/scanner/interface.go`: add `Criticality`, `ScanReport`, and retry config types.
- Modify `internal/scanner/engine.go`: build `ScanReport`, retry retryable errors, record best-effort skips, and ignore excludes for required scanners.
- Modify `internal/scanner/engine_test.go`: replace fail-open tests with report/retry/criticality tests.
- Modify `internal/policy/rules.go`: add `ActionRetryLater`, `ScanErrorMode`, and scan-unavailable result metadata.
- Modify `internal/policy/engine.go`: add `EvaluateReport`, apply `on_scan_error`, preserve deny/allow precedence.
- Modify `internal/policy/engine_test.go`: add required-scanner failure matrix and precedence tests.
- Modify `internal/config/config.go`: add `policy.on_scan_error`, `policy.retry_after`, `scanners.retry`, and `scanners.criticality` parsing/validation.
- Modify `internal/config/config_test.go`: add parsing and validation tests.
- Modify `cmd/shieldoo-gate/main.go`: convert config values, validate criticality after scanner construction, pass scanner options, and pass policy config.
- Modify `cmd/shieldoo-gate/main_test.go`: add post-construction scanner criticality validation tests.
- Modify `internal/adapter/base.go`: add retry-later response and `SCAN_UNAVAILABLE` audit helper.
- Create `internal/adapter/metrics.go`: `scan_error_mode_applied_total{mode,path}`.
- Modify pull adapters:
  - `internal/adapter/pypi/pypi.go`
  - `internal/adapter/npm/npm.go`
  - `internal/adapter/nuget/nuget.go`
  - `internal/adapter/maven/maven.go`
  - `internal/adapter/rubygems/rubygems.go`
  - `internal/adapter/gomod/gomod.go`
  - `internal/adapter/docker/docker.go` (pull path)
- Modify push/sync:
  - `internal/adapter/docker/docker.go` (push path)
  - `internal/adapter/docker/sync.go`
- Modify representative adapter tests:
  - `internal/adapter/pypi/pypi_test.go`
  - `internal/adapter/docker/push_test.go`
  - `internal/adapter/docker/sync_test.go`
- Modify UNKNOWN normalization:
  - `internal/scanner/ai/scanner.go`
  - `internal/scanner/ai/scanner_test.go`
  - `internal/scanner/versiondiff/scanner.go`
  - `internal/scanner/versiondiff/scanner_test.go`
- Modify audit/UI/API docs:
  - `internal/model/audit.go`
  - `internal/config/config.go`
  - `ui/src/pages/AuditLog.tsx`
  - `docs/api/openapi.yaml`
- Modify docs:
  - `config.example.yaml`
  - `docs/policy.md`
  - `docs/scanners.md`
  - `docs/architecture.md`
  - `CLAUDE.md`
  - Create `docs/adr/ADR-011-fail-closed-scanner-errors.md`

`internal/policy/aggregator.go` is intentionally not modified. Required scanner failures are now represented in `ScanReport.Errored` and handled before aggregation; errored results no longer enter `ScanReport.Results`. The existing `if r.Error != nil { continue }` branch becomes dead-but-harmless compatibility behavior for any legacy direct `Evaluate(...)` caller.

---

### Task 1: Scanner Error Taxonomy

**Files:**
- Create: `internal/scanner/errors.go`
- Modify: `internal/scanner/interface.go`
- Test: `internal/scanner/errors_test.go`

- [ ] **Step 1: Write failing error taxonomy tests**

Create `internal/scanner/errors_test.go`:

```go
package scanner

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestScanError_Retryable_ReturnsTrueForRetryableAndOverload(t *testing.T) {
	assert.True(t, NewScanError(ErrKindRetryable, errors.New("down")).Retryable())
	assert.True(t, NewScanError(ErrKindOverload, errors.New("busy")).Retryable())
	assert.False(t, NewScanError(ErrKindTerminal, errors.New("bad input")).Retryable())
}

func TestClassifyScanError_ContextDeadlineIsRetryable(t *testing.T) {
	err := ClassifyScanError(context.DeadlineExceeded)
	require.NotNil(t, err)
	assert.Equal(t, ErrKindRetryable, err.Kind)
}

func TestClassifyScanError_NetTimeoutIsRetryable(t *testing.T) {
	err := ClassifyScanError(timeoutErr{})
	require.NotNil(t, err)
	assert.Equal(t, ErrKindRetryable, err.Kind)
}

func TestClassifyScanError_GRPCResourceExhaustedIsOverload(t *testing.T) {
	err := ClassifyScanError(status.Error(codes.ResourceExhausted, "busy"))
	require.NotNil(t, err)
	assert.Equal(t, ErrKindOverload, err.Kind)
}

func TestClassifyScanError_GRPCInvalidArgumentIsTerminal(t *testing.T) {
	err := ClassifyScanError(status.Error(codes.InvalidArgument, "bad artifact"))
	require.NotNil(t, err)
	assert.Equal(t, ErrKindTerminal, err.Kind)
}

func TestClassifyScanError_PreservesExistingScanError(t *testing.T) {
	original := NewScanError(ErrKindOverload, errors.New("scanner overloaded"))
	classified := ClassifyScanError(original)
	require.NotNil(t, classified)
	assert.Same(t, original, classified)
}
```

- [ ] **Step 2: Run the taxonomy tests and verify they fail**

Run:

```bash
go test ./internal/scanner -run 'Test.*ScanError|TestClassifyScanError' -count=1
```

Expected: FAIL with undefined `NewScanError`, `ErrKindRetryable`, and `ClassifyScanError`.

- [ ] **Step 3: Add scanner error taxonomy**

Create `internal/scanner/errors.go`:

```go
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ScanErrorKind int

const (
	ErrKindNone ScanErrorKind = iota
	ErrKindRetryable
	ErrKindTerminal
	ErrKindOverload
)

func (k ScanErrorKind) String() string {
	switch k {
	case ErrKindRetryable:
		return "retryable"
	case ErrKindTerminal:
		return "terminal"
	case ErrKindOverload:
		return "overload"
	default:
		return "none"
	}
}

type ScanError struct {
	Kind ScanErrorKind
	Err  error
}

func NewScanError(kind ScanErrorKind, err error) *ScanError {
	if err == nil {
		err = errors.New("scanner error")
	}
	if kind == ErrKindNone {
		kind = ErrKindRetryable
	}
	return &ScanError{Kind: kind, Err: err}
}

func (e *ScanError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s scanner error: %v", e.Kind.String(), e.Err)
}

func (e *ScanError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ScanError) Retryable() bool {
	return e != nil && (e.Kind == ErrKindRetryable || e.Kind == ErrKindOverload)
}

func ClassifyScanError(err error) *ScanError {
	if err == nil {
		return nil
	}
	var scanErr *ScanError
	if errors.As(err, &scanErr) {
		return scanErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return NewScanError(ErrKindRetryable, err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return NewScanError(ErrKindRetryable, err)
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.ResourceExhausted:
			return NewScanError(ErrKindOverload, err)
		case codes.Unavailable, codes.DeadlineExceeded:
			return NewScanError(ErrKindRetryable, err)
		case codes.InvalidArgument, codes.NotFound, codes.Unimplemented:
			return NewScanError(ErrKindTerminal, err)
		}
	}
	return NewScanError(ErrKindRetryable, err)
}
```

- [ ] **Step 4: Add report/config types**

Modify `internal/scanner/interface.go` after `type ScanResult struct`:

```go
type Criticality string

const (
	CriticalityRequired   Criticality = "required"
	CriticalityBestEffort Criticality = "best_effort"
)

type ScanRetryConfig struct {
	MaxAttempts int
	Backoff     time.Duration
}

type ScanReport struct {
	Expected []string
	Results  []ScanResult
	Errored  map[string]*ScanError
	Skipped  []string
}

func (r ScanReport) SuccessfulResults() []ScanResult {
	return r.Results
}
```

- [ ] **Step 5: Run taxonomy tests**

Run:

```bash
go test ./internal/scanner -run 'Test.*ScanError|TestClassifyScanError' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/errors.go internal/scanner/errors_test.go internal/scanner/interface.go
git commit -m "feat: add scanner error taxonomy"
```

---

### Task 2: ScanReport, Retry, and Required Exclusion Contract

**Files:**
- Modify: `internal/scanner/engine.go`
- Create: `internal/scanner/metrics.go`
- Modify: `internal/scanner/engine_test.go`

- [ ] **Step 1: Replace engine fail-open tests with report/retry tests**

In `internal/scanner/engine_test.go`, replace `TestEngine_ScanAll_Timeout_ReturnsErrorNotMalicious` and `TestEngine_ScanAll_ScannerError_FailsOpen` with:

```go
func TestEngine_ScanAll_ScannerError_RecordsErroredScanner(t *testing.T) {
	failing := &mockScanner{
		name:       "guarddog",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			return ScanResult{}, errors.New("scanner crashed")
		},
	}

	engine := NewEngine(
		[]Scanner{failing},
		30*time.Second,
		0,
		WithCriticality(map[string]Criticality{"guarddog": CriticalityRequired}),
	)
	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Equal(t, []string{"guarddog"}, report.Expected)
	assert.Empty(t, report.Results)
	require.Contains(t, report.Errored, "guarddog")
	assert.Equal(t, ErrKindRetryable, report.Errored["guarddog"].Kind)
}

func TestEngine_ScanAll_RetriesRetryableErrors(t *testing.T) {
	attempts := 0
	flaky := &mockScanner{
		name:       "guarddog",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			attempts++
			if attempts == 1 {
				return ScanResult{}, NewScanError(ErrKindRetryable, errors.New("bridge down"))
			}
			return ScanResult{Verdict: VerdictClean, Confidence: 1, ScannerID: "guarddog"}, nil
		},
	}

	engine := NewEngine(
		[]Scanner{flaky},
		time.Second,
		0,
		WithRetry(2, time.Millisecond),
	)
	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
	require.Len(t, report.Results, 1)
	assert.Empty(t, report.Errored)
}

func TestEngine_ScanAll_DoesNotRetryTerminalErrors(t *testing.T) {
	attempts := 0
	badArtifact := &mockScanner{
		name:       "guarddog",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			attempts++
			return ScanResult{}, NewScanError(ErrKindTerminal, errors.New("unsupported archive"))
		},
	}

	engine := NewEngine(
		[]Scanner{badArtifact},
		time.Second,
		0,
		WithRetry(3, time.Millisecond),
	)
	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Equal(t, 1, attempts)
	require.Contains(t, report.Errored, "guarddog")
	assert.Equal(t, ErrKindTerminal, report.Errored["guarddog"].Kind)
}

func TestEngine_ScanAll_RequiredScannerCannotBeExcluded(t *testing.T) {
	required := &mockScanner{
		name:       "guarddog",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			return ScanResult{Verdict: VerdictClean, ScannerID: "guarddog"}, nil
		},
	}

	engine := NewEngine(
		[]Scanner{required},
		time.Second,
		0,
		WithCriticality(map[string]Criticality{"guarddog": CriticalityRequired}),
	)
	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI}, "guarddog")
	require.NoError(t, err)
	assert.Equal(t, []string{"guarddog"}, report.Expected)
	require.Len(t, report.Results, 1)
	assert.Empty(t, report.Skipped)
}

func TestEngine_ScanAll_BestEffortExcludeIsRecordedAsSkipped(t *testing.T) {
	bestEffort := &mockScanner{
		name:       "ai-scanner",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			t.Fatal("excluded best-effort scanner should not run")
			return ScanResult{}, nil
		},
	}

	engine := NewEngine([]Scanner{bestEffort}, time.Second, 0)
	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI}, "ai-scanner")
	require.NoError(t, err)
	assert.Empty(t, report.Expected)
	assert.Equal(t, []string{"ai-scanner"}, report.Skipped)
}
```

Also update existing tests:

```go
report, err := engine.ScanAll(...)
require.NoError(t, err)
assert.Len(t, report.Results, 2)
```

- [ ] **Step 2: Run scanner tests and verify they fail**

Run:

```bash
go test ./internal/scanner -run 'TestEngine_ScanAll' -count=1
```

Expected: FAIL because `ScanAll` still returns `[]ScanResult`.

- [ ] **Step 3: Add scanner metrics**

Create `internal/scanner/metrics.go`:

```go
package scanner

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	scannerErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "shieldoo_gate_scanner_errors_total",
			Help: "Total number of inline scanner errors by scanner and kind.",
		},
		[]string{"scanner", "kind"},
	)

	circuitBreakerState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "shieldoo_gate_circuit_breaker_state",
			Help: "Inline scanner circuit breaker state, 1=open and 0=closed.",
		},
		[]string{"scanner"},
	)
)
```

Remove the unused `ScannerErrorsTotal` definition from `internal/api/metrics.go` to avoid duplicate metric registration.

- [ ] **Step 4: Update engine options and report logic**

Modify `internal/scanner/engine.go`:

```go
type Engine struct {
	scanners []Scanner
	timeout  time.Duration
	sem      *semaphore.Weighted

	retryMaxAttempts int
	retryBackoff     time.Duration
	criticality      map[string]Criticality
	breakers         map[string]*scanCircuit
}

type EngineOption func(*Engine)

func WithRetry(maxAttempts int, backoff time.Duration) EngineOption {
	return func(e *Engine) {
		if maxAttempts > 0 {
			e.retryMaxAttempts = maxAttempts
		}
		if backoff > 0 {
			e.retryBackoff = backoff
		}
	}
}

func WithCriticality(criticality map[string]Criticality) EngineOption {
	return func(e *Engine) {
		e.criticality = make(map[string]Criticality, len(criticality))
		for name, value := range criticality {
			e.criticality[name] = value
		}
	}
}

func NewEngine(scanners []Scanner, timeout time.Duration, maxConcurrentScans int64, opts ...EngineOption) *Engine {
	var sem *semaphore.Weighted
	if maxConcurrentScans > 0 {
		sem = semaphore.NewWeighted(maxConcurrentScans)
	}
	e := &Engine{
		scanners:         scanners,
		timeout:          timeout,
		sem:              sem,
		retryMaxAttempts: 1,
		retryBackoff:     200 * time.Millisecond,
		criticality:      map[string]Criticality{},
		breakers:         map[string]*scanCircuit{},
	}
	for _, opt := range opts {
		opt(e)
	}
	for _, sc := range scanners {
		e.breakers[sc.Name()] = newScanCircuit(5, time.Minute)
	}
	return e
}

func (e *Engine) RegisteredScannerNames() []string {
	names := make([]string, 0, len(e.scanners))
	for _, s := range e.scanners {
		names = append(names, s.Name())
	}
	return names
}

func (e *Engine) criticalityFor(name string) Criticality {
	if e.criticality[name] == CriticalityRequired {
		return CriticalityRequired
	}
	return CriticalityBestEffort
}
```

Replace `ScanAll` with a `ScanReport` implementation:

```go
func (e *Engine) ScanAll(ctx context.Context, artifact Artifact, excludeNames ...string) (ScanReport, error) {
	excludeSet := make(map[string]struct{}, len(excludeNames))
	for _, n := range excludeNames {
		excludeSet[n] = struct{}{}
	}

	var applicable []Scanner
	report := ScanReport{Errored: map[string]*ScanError{}}
	for _, s := range e.scanners {
		supports := false
		for _, eco := range s.SupportedEcosystems() {
			if eco == artifact.Ecosystem {
				supports = true
				break
			}
		}
		if !supports {
			continue
		}
		if _, excluded := excludeSet[s.Name()]; excluded && e.criticalityFor(s.Name()) != CriticalityRequired {
			report.Skipped = append(report.Skipped, s.Name())
			continue
		}
		applicable = append(applicable, s)
		report.Expected = append(report.Expected, s.Name())
	}

	if len(applicable) == 0 {
		if len(artifact.ExtraLicenses) > 0 {
			report.Results = append(report.Results, ScanResult{
				Verdict:   VerdictClean,
				ScannerID: "extra-licenses",
				ScannedAt: time.Now(),
				Licenses:  artifact.ExtraLicenses,
			})
		}
		return report, nil
	}

	if e.sem != nil {
		if err := e.sem.Acquire(ctx, 1); err != nil {
			scanErr := ClassifyScanError(err)
			for _, sc := range applicable {
				report.Errored[sc.Name()] = scanErr
				scannerErrorsTotal.WithLabelValues(sc.Name(), scanErr.Kind.String()).Inc()
			}
			return report, err
		}
		defer e.sem.Release(1)
	}

	scanCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, s := range applicable {
		wg.Add(1)
		go func(sc Scanner) {
			defer wg.Done()
			result, scanErr := e.scanOne(scanCtx, sc, artifact)
			mu.Lock()
			defer mu.Unlock()
			if scanErr != nil {
				report.Errored[sc.Name()] = scanErr
				scannerErrorsTotal.WithLabelValues(sc.Name(), scanErr.Kind.String()).Inc()
				return
			}
			report.Results = append(report.Results, result)
		}(s)
	}
	wg.Wait()

	if len(artifact.ExtraLicenses) > 0 {
		report.Results = append(report.Results, ScanResult{
			Verdict:   VerdictClean,
			ScannerID: "extra-licenses",
			ScannedAt: time.Now(),
			Licenses:  artifact.ExtraLicenses,
		})
	}

	return report, nil
}
```

Add helpers in the same file:

```go
func (e *Engine) scanOne(ctx context.Context, sc Scanner, artifact Artifact) (ScanResult, *ScanError) {
	breaker := e.breakers[sc.Name()]
	if breaker != nil && breaker.isOpen() {
		circuitBreakerState.WithLabelValues(sc.Name()).Set(1)
		return ScanResult{}, NewScanError(ErrKindOverload, fmt.Errorf("%s scanner circuit open", sc.Name()))
	}
	circuitBreakerState.WithLabelValues(sc.Name()).Set(0)

	attempts := e.retryMaxAttempts
	if attempts < 1 {
		attempts = 1
	}
	backoff := e.retryBackoff
	if backoff <= 0 {
		backoff = 200 * time.Millisecond
	}

	var lastErr *ScanError
	for attempt := 1; attempt <= attempts; attempt++ {
		start := time.Now()
		result, err := sc.Scan(ctx, artifact)
		if err == nil && result.Error != nil {
			err = result.Error
		}
		if err == nil {
			if result.ScannerID == "" {
				result.ScannerID = sc.Name()
			}
			if result.ScannerVersion == "" {
				result.ScannerVersion = sc.Version()
			}
			result.Duration = time.Since(start)
			result.ScannedAt = start
			if breaker != nil {
				breaker.recordSuccess()
			}
			return result, nil
		}

		lastErr = ClassifyScanError(err)
		if !lastErr.Retryable() || attempt == attempts {
			break
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			lastErr = ClassifyScanError(ctx.Err())
			attempt = attempts
		case <-timer.C:
		}
		backoff *= 2
	}

	if breaker != nil {
		breaker.recordFailure()
	}
	return ScanResult{}, lastErr
}
```

Add a private circuit implementation in `internal/scanner/engine.go` or a new `internal/scanner/circuit.go`:

```go
type scanCircuit struct {
	mu          sync.Mutex
	threshold   int
	cooldown    time.Duration
	failures    int
	openUntil   time.Time
}

func newScanCircuit(threshold int, cooldown time.Duration) *scanCircuit {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = time.Minute
	}
	return &scanCircuit{threshold: threshold, cooldown: cooldown}
}

func (c *scanCircuit) isOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.openUntil)
}

func (c *scanCircuit) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.openUntil = time.Time{}
}

func (c *scanCircuit) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures >= c.threshold {
		c.openUntil = time.Now().Add(c.cooldown)
	}
}
```

Add imports to `engine.go`:

```go
import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)
```

- [ ] **Step 5: Run scanner tests**

Run:

```bash
go test ./internal/scanner -count=1
```

Expected: PASS after updating existing tests to read `report.Results`.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/engine.go internal/scanner/metrics.go internal/scanner/engine_test.go internal/api/metrics.go
git commit -m "feat: report scanner completeness"
```

---

### Task 3: Policy Scan Error Modes

**Files:**
- Modify: `internal/policy/rules.go`
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/engine_test.go`

- [ ] **Step 1: Add failing policy tests**

Append to `internal/policy/engine_test.go`:

```go
func requiredErroredReport() scanner.ScanReport {
	return scanner.ScanReport{
		Expected: []string{"guarddog"},
		Errored: map[string]*scanner.ScanError{
			"guarddog": scanner.NewScanError(scanner.ErrKindOverload, errors.New("scanner overloaded")),
		},
	}
}

func TestPolicyEngine_RequiredScannerError_QuarantineModeReturnsRetryLater(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.OnScanError = policy.ScanErrorModeQuarantine
	cfg.ScannerCriticality = map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	engine := policy.NewEngine(cfg, nil)

	result := engine.EvaluateReport(context.Background(), pypiArtifact("pkg", "1.0.0"), requiredErroredReport())

	assert.Equal(t, policy.ActionRetryLater, result.Action)
	assert.Len(t, result.ScanUnavailable, 1)
	assert.Equal(t, "guarddog", result.ScanUnavailable[0].Scanner)
	assert.Equal(t, "overload", result.ScanUnavailable[0].Kind)
	assert.Equal(t, "retry_later", result.ScanUnavailable[0].Mode)
}

func TestPolicyEngine_RequiredScannerError_BlockModeReturnsBlock(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.OnScanError = policy.ScanErrorModeBlock
	cfg.ScannerCriticality = map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	engine := policy.NewEngine(cfg, nil)

	result := engine.EvaluateReport(context.Background(), pypiArtifact("pkg", "1.0.0"), requiredErroredReport())

	assert.Equal(t, policy.ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "required scanner unavailable")
	require.Len(t, result.ScanUnavailable, 1)
	assert.Equal(t, "block", result.ScanUnavailable[0].Mode)
}

func TestPolicyEngine_RequiredScannerError_FailOpenModeAllowsClean(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.OnScanError = policy.ScanErrorModeFailOpen
	cfg.ScannerCriticality = map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	engine := policy.NewEngine(cfg, nil)

	result := engine.EvaluateReport(context.Background(), pypiArtifact("pkg", "1.0.0"), requiredErroredReport())

	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Len(t, result.ScanUnavailable, 1)
	assert.Equal(t, "fail_open", result.ScanUnavailable[0].Mode)
}

func TestPolicyEngine_AllowlistBypassesRequiredScannerError(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Allowlist = []string{"pypi:pkg:==1.0.0"}
	cfg.OnScanError = policy.ScanErrorModeQuarantine
	cfg.ScannerCriticality = map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	engine := policy.NewEngine(cfg, nil)

	result := engine.EvaluateReport(context.Background(), pypiArtifact("pkg", "1.0.0"), requiredErroredReport())

	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Empty(t, result.ScanUnavailable)
}

func TestPolicyEngine_BestEffortScannerErrorStillAllowsClean(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.OnScanError = policy.ScanErrorModeQuarantine
	cfg.ScannerCriticality = map[string]scanner.Criticality{"guarddog": scanner.CriticalityBestEffort}
	engine := policy.NewEngine(cfg, nil)

	result := engine.EvaluateReport(context.Background(), pypiArtifact("pkg", "1.0.0"), requiredErroredReport())

	assert.Equal(t, policy.ActionAllow, result.Action)
}
```

Add `errors` to the test imports.

- [ ] **Step 2: Run policy tests and verify they fail**

Run:

```bash
go test ./internal/policy -run 'RequiredScannerError|AllowlistBypasses|BestEffortScannerError' -count=1
```

Expected: FAIL with undefined `EvaluateReport`, `ActionRetryLater`, and scan error mode types.

- [ ] **Step 3: Add policy types**

Modify `internal/policy/rules.go`:

```go
const (
	ActionAllow            Action = "allow"
	ActionBlock            Action = "block"
	ActionQuarantine       Action = "quarantine"
	ActionAllowWithWarning Action = "allow_with_warning"
	ActionRetryLater       Action = "retry_later"
)

type ScanErrorMode string

const (
	ScanErrorModeQuarantine ScanErrorMode = "quarantine"
	ScanErrorModeBlock      ScanErrorMode = "block"
	ScanErrorModeFailOpen   ScanErrorMode = "fail_open"
)

type ScanUnavailable struct {
	Scanner string
	Kind    string
	Mode    string
}

type PolicyResult struct {
	Action          Action
	Reason          string
	Warnings        []string
	ScanUnavailable []ScanUnavailable
}
```

- [ ] **Step 4: Extend policy config and constructor defaults**

Modify `internal/policy/engine.go` `EngineConfig`:

```go
type EngineConfig struct {
	Mode                        PolicyMode
	BlockIfVerdict              scanner.Verdict
	QuarantineIfVerdict         scanner.Verdict
	MinimumConfidence           float32
	BehavioralMinimumConfidence float32
	Allowlist                   []string
	AITriage                    config.AITriageConfig
	OnScanError                 ScanErrorMode
	RetryAfter                  time.Duration
	ScannerCriticality          map[string]scanner.Criticality
}
```

In `NewEngine`, default mode and copy criticality:

```go
if cfg.OnScanError == "" {
	cfg.OnScanError = ScanErrorModeQuarantine
}
if cfg.RetryAfter <= 0 {
	cfg.RetryAfter = 30 * time.Second
}
if cfg.ScannerCriticality == nil {
	cfg.ScannerCriticality = map[string]scanner.Criticality{}
}
```

Add a getter for adapters:

```go
func (e *Engine) RetryAfter() time.Duration {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.cfg.RetryAfter > 0 {
		return e.cfg.RetryAfter
	}
	return 30 * time.Second
}
```

- [ ] **Step 5: Add `EvaluateReport` and keep wrapper**

Replace current `Evaluate` body with a wrapper and move the old logic into `EvaluateReport`:

```go
func (e *Engine) Evaluate(ctx context.Context, artifact scanner.Artifact, scanResults []scanner.ScanResult) PolicyResult {
	return e.EvaluateReport(ctx, artifact, scanner.ScanReport{Results: scanResults, Errored: map[string]*scanner.ScanError{}})
}

func (e *Engine) EvaluateReport(ctx context.Context, artifact scanner.Artifact, report scanner.ScanReport) PolicyResult {
	// DB override check: deny and allow both intentionally bypass scanner availability.
	if id, kind, ok := e.lookupOverride(ctx, artifact.Ecosystem, artifact.Name, artifact.Version); ok {
		switch kind {
		case OverrideKindDeny:
			return PolicyResult{
				Action: ActionBlock,
				Reason: fmt.Sprintf("project policy override (deny): %s:%s:%s [override_id=%d]", artifact.Ecosystem, artifact.Name, artifact.Version, id),
			}
		case OverrideKindAllow:
			return PolicyResult{
				Action: ActionAllow,
				Reason: fmt.Sprintf("policy override: %s:%s:%s", artifact.Ecosystem, artifact.Name, artifact.Version),
			}
		}
	}

	if isAllowlisted(artifact, e.allowlist) {
		return PolicyResult{Action: ActionAllow, Reason: "artifact is in allowlist"}
	}

	unavailable := e.requiredScannerUnavailable(report)

	licResult, licHandled := e.evaluateLicenses(ctx, artifact, report.Results)
	if licHandled {
		if len(unavailable) > 0 {
			licResult.ScanUnavailable = unavailable
		}
		return licResult
	}
	licWarnings := licResult.Warnings

	if len(unavailable) > 0 {
		switch e.cfg.OnScanError {
		case ScanErrorModeBlock:
			return PolicyResult{
				Action:          ActionBlock,
				Reason:          "required scanner unavailable",
				Warnings:        licWarnings,
				ScanUnavailable: unavailable,
			}
		case ScanErrorModeFailOpen:
			log.Warn().
				Str("artifact", artifact.ID).
				Int("scanner_errors", len(unavailable)).
				Msg("policy: required scanner unavailable, fail_open mode allows verdict aggregation")
		default:
			return PolicyResult{
				Action:          ActionRetryLater,
				Reason:          "required scanner unavailable",
				Warnings:        licWarnings,
				ScanUnavailable: unavailable,
			}
		}
	}

	aggCfg := AggregationConfig{
		MinConfidence:           e.cfg.MinimumConfidence,
		BehavioralMinConfidence: e.cfg.BehavioralMinimumConfidence,
	}
	agg := Aggregate(report.Results, aggCfg)

	var result PolicyResult
	switch {
	case agg.Verdict == scanner.VerdictMalicious:
		result = PolicyResult{Action: ActionBlock, Reason: fmt.Sprintf("verdict %s meets block threshold", agg.Verdict)}
	case agg.Verdict == scanner.VerdictSuspicious:
		result = e.evaluateSuspicious(ctx, artifact, &agg)
	default:
		result = PolicyResult{Action: ActionAllow, Reason: fmt.Sprintf("verdict %s is below action thresholds", agg.Verdict)}
	}
	if len(licWarnings) > 0 {
		result.Warnings = append(licWarnings, result.Warnings...)
	}
	if len(unavailable) > 0 {
		result.ScanUnavailable = unavailable
	}
	return result
}
```

Add helper:

```go
func (e *Engine) requiredScannerUnavailable(report scanner.ScanReport) []ScanUnavailable {
	if len(report.Errored) == 0 {
		return nil
	}
	mode := e.cfg.OnScanError
	if mode == "" {
		mode = ScanErrorModeQuarantine
	}
	appliedMode := string(mode)
	if mode == ScanErrorModeQuarantine {
		appliedMode = string(ActionRetryLater)
	}
	out := make([]ScanUnavailable, 0, len(report.Errored))
	for scannerName, err := range report.Errored {
		if e.cfg.ScannerCriticality[scannerName] != scanner.CriticalityRequired {
			continue
		}
		kind := scanner.ErrKindRetryable.String()
		if err != nil {
			kind = err.Kind.String()
		}
		out = append(out, ScanUnavailable{
			Scanner: scannerName,
			Kind:    kind,
			Mode:    appliedMode,
		})
	}
	return out
}
```

- [ ] **Step 6: Run policy tests**

Run:

```bash
go test ./internal/policy -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/policy/rules.go internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat: apply policy to scanner failures"
```

---

### Task 4: Config Parsing and Startup Scanner Validation

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `cmd/shieldoo-gate/main.go`
- Modify: `cmd/shieldoo-gate/main_test.go`
- Modify: `config.example.yaml`

- [ ] **Step 1: Add failing config tests**

Append to `internal/config/config_test.go`:

```go
func TestLoad_ScanErrorPolicyDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
`), 0o644))

	cfg, err := Load(cfgPath)
	require.NoError(t, err)

	assert.Equal(t, "quarantine", cfg.Policy.OnScanError)
	assert.Equal(t, "30s", cfg.Policy.RetryAfter)
	assert.Equal(t, 3, cfg.Scanners.Retry.MaxAttempts)
	assert.Equal(t, "200ms", cfg.Scanners.Retry.Backoff)
}

func TestValidate_InvalidOnScanError_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Policy.OnScanError = "permit"

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy.on_scan_error")
}

func TestValidate_InvalidScannerCriticality_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Scanners.Criticality = map[string]string{"guarddog": "mandatory"}

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "scanners.criticality.guarddog")
}

func TestValidate_InvalidScannerRetryBackoff_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Scanners.Retry.Backoff = "soon"

	err := cfg.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "scanners.retry.backoff")
}
```

- [ ] **Step 2: Add failing startup validation tests**

Append to `cmd/shieldoo-gate/main_test.go`:

```go
func TestValidateScannerCriticality_UnknownBestEffortScannerReturnsError(t *testing.T) {
	err := validateScannerCriticality(
		[]scanner.Scanner{criticalityTestScanner{name: "guarddog"}},
		map[string]scanner.Criticality{"guarddogg": scanner.CriticalityBestEffort},
		policy.ScanErrorModeQuarantine,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "guarddogg")
}

func TestValidateScannerCriticality_MissingRequiredScannerReturnsError(t *testing.T) {
	err := validateScannerCriticality(
		[]scanner.Scanner{criticalityTestScanner{name: "builtin-threat-feed"}},
		map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired},
		policy.ScanErrorModeQuarantine,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "required scanner")
}

func TestValidateScannerCriticality_MissingRequiredScannerAllowedInFailOpen(t *testing.T) {
	err := validateScannerCriticality(
		[]scanner.Scanner{criticalityTestScanner{name: "builtin-threat-feed"}},
		map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired},
		policy.ScanErrorModeFailOpen,
	)

	require.NoError(t, err)
}
```

Add this helper type to `cmd/shieldoo-gate/main_test.go`:

```go
type criticalityTestScanner struct{ name string }

func (n criticalityTestScanner) Name() string { return n.name }
func (n criticalityTestScanner) Version() string { return "test" }
func (n criticalityTestScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI}
}
func (n criticalityTestScanner) Scan(context.Context, scanner.Artifact) (scanner.ScanResult, error) {
	return scanner.ScanResult{ScannerID: n.name, Verdict: scanner.VerdictClean}, nil
}
func (n criticalityTestScanner) HealthCheck(context.Context) error { return nil }
```

- [ ] **Step 3: Run tests and verify they fail**

Run:

```bash
go test ./internal/config ./cmd/shieldoo-gate -run 'ScanError|ScannerCriticality|ScannerRetry' -count=1
```

Expected: FAIL with missing config fields and validation helpers.

- [ ] **Step 4: Add config structs, defaults, and validation**

Modify `internal/config/config.go`:

```go
type ScannersConfig struct {
	Parallel    bool              `mapstructure:"parallel"`
	Timeout     string            `mapstructure:"timeout"`
	Retry       ScannerRetryConfig `mapstructure:"retry"`
	Criticality map[string]string `mapstructure:"criticality"`
	GuardDog    GuardDogConfig    `mapstructure:"guarddog"`
	Trivy       TrivyConfig       `mapstructure:"trivy"`
	OSV         OSVConfig         `mapstructure:"osv"`
	Sandbox     SandboxConfig     `mapstructure:"sandbox"`
	AI          AIConfig          `mapstructure:"ai"`
	Typosquat   TyposquatConfig   `mapstructure:"typosquat"`
	VersionDiff VersionDiffConfig `mapstructure:"version_diff"`
	Reputation  ReputationConfig  `mapstructure:"reputation"`
}

type ScannerRetryConfig struct {
	MaxAttempts int    `mapstructure:"max_attempts"`
	Backoff     string `mapstructure:"backoff"`
}

type PolicyConfig struct {
	Mode                        string              `mapstructure:"mode"`
	BlockIfVerdict              string              `mapstructure:"block_if_verdict"`
	QuarantineIfVerdict         string              `mapstructure:"quarantine_if_verdict"`
	MinimumConfidence           float32             `mapstructure:"minimum_confidence"`
	BehavioralMinimumConfidence float32             `mapstructure:"behavioral_minimum_confidence"`
	OnScanError                 string              `mapstructure:"on_scan_error"`
	RetryAfter                  string              `mapstructure:"retry_after"`
	AITriage                    AITriageConfig      `mapstructure:"ai_triage"`
	Allowlist                   []string            `mapstructure:"allowlist"`
	TagMutability               TagMutabilityConfig `mapstructure:"tag_mutability"`
	Licenses                    LicensePolicyConfig `mapstructure:"licenses"`
}
```

Add defaults in `Load`:

```go
v.SetDefault("policy.on_scan_error", "quarantine")
v.SetDefault("policy.retry_after", "30s")
v.SetDefault("scanners.retry.max_attempts", 3)
v.SetDefault("scanners.retry.backoff", "200ms")
```

Add to `validatePolicy()`:

```go
switch c.Policy.OnScanError {
case "", "quarantine", "block", "fail_open":
default:
	return fmt.Errorf("config: policy.on_scan_error must be 'quarantine'|'block'|'fail_open', got %q", c.Policy.OnScanError)
}
if c.Policy.RetryAfter != "" {
	d, err := time.ParseDuration(c.Policy.RetryAfter)
	if err != nil || d <= 0 {
		return fmt.Errorf("config: policy.retry_after %q is not a positive duration", c.Policy.RetryAfter)
	}
}
```

Add a new validation helper and call it from `Validate()` after `validatePolicy()`:

```go
func (c *Config) validateScannerFailureConfig() error {
	if c.Scanners.Retry.MaxAttempts < 0 {
		return fmt.Errorf("config: scanners.retry.max_attempts must be >= 0, got %d", c.Scanners.Retry.MaxAttempts)
	}
	if c.Scanners.Retry.Backoff != "" {
		d, err := time.ParseDuration(c.Scanners.Retry.Backoff)
		if err != nil || d <= 0 {
			return fmt.Errorf("config: scanners.retry.backoff %q is not a positive duration", c.Scanners.Retry.Backoff)
		}
	}
	for name, value := range c.Scanners.Criticality {
		switch value {
		case "required", "best_effort":
		default:
			return fmt.Errorf("config: scanners.criticality.%s must be 'required'|'best_effort', got %q", name, value)
		}
	}
	return nil
}
```

- [ ] **Step 5: Add startup validation helpers**

In `cmd/shieldoo-gate/main.go`, add helpers near `parseDuration`/config helpers:

```go
func scanErrorModeFromConfig(raw string) policy.ScanErrorMode {
	switch raw {
	case "block":
		return policy.ScanErrorModeBlock
	case "fail_open":
		return policy.ScanErrorModeFailOpen
	default:
		return policy.ScanErrorModeQuarantine
	}
}

func scannerCriticalityFromConfig(raw map[string]string) map[string]scanner.Criticality {
	out := make(map[string]scanner.Criticality, len(raw))
	for name, value := range raw {
		if value == "required" {
			out[name] = scanner.CriticalityRequired
		} else {
			out[name] = scanner.CriticalityBestEffort
		}
	}
	return out
}

func validateScannerCriticality(scanners []scanner.Scanner, criticality map[string]scanner.Criticality, mode policy.ScanErrorMode) error {
	registered := make(map[string]struct{}, len(scanners))
	for _, sc := range scanners {
		registered[sc.Name()] = struct{}{}
	}
	for name, value := range criticality {
		if _, ok := registered[name]; ok {
			continue
		}
		if value == scanner.CriticalityRequired && mode == policy.ScanErrorModeFailOpen {
			log.Warn().Str("scanner", name).Msg("required scanner is not registered, allowed because policy.on_scan_error=fail_open")
			continue
		}
		if value == scanner.CriticalityRequired {
			return fmt.Errorf("required scanner %q is configured but not registered", name)
		}
		return fmt.Errorf("scanner %q has configured criticality but is not registered", name)
	}
	return nil
}
```

After scanner construction and before `scanner.NewEngine(...)`, wire options:

```go
scanErrorMode := scanErrorModeFromConfig(cfg.Policy.OnScanError)
scannerCriticality := scannerCriticalityFromConfig(cfg.Scanners.Criticality)
if err := validateScannerCriticality(scanners, scannerCriticality, scanErrorMode); err != nil {
	log.Fatal().Err(err).Msg("invalid scanner criticality configuration")
}

retryAttempts := cfg.Scanners.Retry.MaxAttempts
if retryAttempts == 0 {
	retryAttempts = 3
}
retryBackoff := parseDuration(cfg.Scanners.Retry.Backoff, 200*time.Millisecond)

scanEngine := scanner.NewEngine(
	scanners,
	scanTimeout,
	32,
	scanner.WithRetry(retryAttempts, retryBackoff),
	scanner.WithCriticality(scannerCriticality),
)
```

When constructing the policy engine config, add:

```go
OnScanError:        scanErrorMode,
RetryAfter:         parseDuration(cfg.Policy.RetryAfter, 30*time.Second),
ScannerCriticality: scannerCriticality,
```

- [ ] **Step 6: Update `config.example.yaml`**

Add under `policy:`:

```yaml
  on_scan_error: "quarantine"          # quarantine(503/reject/skip) | block | fail_open
  retry_after: "30s"                   # Retry-After hint for pull-path 503 responses
```

Add under `scanners:`:

```yaml
  retry:
    max_attempts: 3
    backoff: "200ms"
  criticality:
    builtin-threat-feed: "required"
    guarddog: "required"
    ai-scanner: "best_effort"
    version-diff: "best_effort"
    builtin-reputation: "best_effort"
```

- [ ] **Step 7: Run config/startup tests**

Run:

```bash
go test ./internal/config ./cmd/shieldoo-gate -run 'ScanError|ScannerCriticality|ScannerRetry' -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go cmd/shieldoo-gate/main.go cmd/shieldoo-gate/main_test.go config.example.yaml
git commit -m "feat: configure scanner failure policy"
```

---

### Task 5: Audit Event and Shared Retry-Later Adapter Helper

**Files:**
- Modify: `internal/model/audit.go`
- Modify: `internal/config/config.go`
- Modify: `internal/adapter/base.go`
- Create: `internal/adapter/metrics.go`
- Modify: `ui/src/pages/AuditLog.tsx`
- Modify: `docs/api/openapi.yaml`

- [ ] **Step 1: Add audit event constant and alert allow-list**

Modify `internal/model/audit.go` near license/scanner events:

```go
EventScanUnavailable EventType = "SCAN_UNAVAILABLE"
```

Modify `knownEventTypes` in `internal/config/config.go`:

```go
"SCAN_UNAVAILABLE": true,
```

- [ ] **Step 2: Add adapter metrics**

Create `internal/adapter/metrics.go`:

```go
package adapter

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var scanErrorModeAppliedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "shieldoo_gate_scan_error_mode_applied_total",
		Help: "Total number of required scanner failure policy decisions by mode and path.",
	},
	[]string{"mode", "path"},
)
```

- [ ] **Step 3: Add helper functions in `internal/adapter/base.go`**

Add imports:

```go
import (
	"crypto/rand"
	"encoding/json"
	"math/big"
)
```

Add helpers after `WriteJSONError`:

```go
func WriteRetryLater(w http.ResponseWriter, artifactID, reason string, retryAfter time.Duration) {
	if retryAfter <= 0 {
		retryAfter = 30 * time.Second
	}
	value := retryAfter + retryAfterJitter(retryAfter)
	w.Header().Set("Retry-After", fmt.Sprintf("%.0f", value.Seconds()))
	WriteJSONError(w, http.StatusServiceUnavailable, ErrorResponse{
		Error:    "scanner unavailable",
		Artifact: artifactID,
		Reason:   reason,
	})
}

func retryAfterJitter(base time.Duration) time.Duration {
	max := base / 5
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func AuditScanUnavailable(
	ctx context.Context,
	db *config.GateDB,
	result policy.PolicyResult,
	artifactID string,
	path string,
	clientIP string,
	userAgent string,
) {
	for _, unavailable := range result.ScanUnavailable {
		meta, err := json.Marshal(struct {
			Scanner string `json:"scanner"`
			Kind    string `json:"kind"`
			Mode    string `json:"mode"`
			Path    string `json:"path"`
		}{
			Scanner: unavailable.Scanner,
			Kind:    unavailable.Kind,
			Mode:    string(unavailable.Mode),
			Path:    path,
		})
		if err != nil {
			log.Warn().Err(err).Str("artifact", artifactID).Msg("adapter: failed to marshal scanner unavailable audit metadata")
			continue
		}
		_ = WriteAuditLogCtx(ctx, db, model.AuditEntry{
			EventType:    model.EventScanUnavailable,
			ArtifactID:   artifactID,
			ClientIP:     clientIP,
			UserAgent:    userAgent,
			Reason:       result.Reason,
			MetadataJSON: string(meta),
		})
		scanErrorModeAppliedTotal.WithLabelValues(string(unavailable.Mode), path).Inc()
	}
}
```

Call `AuditScanUnavailable` once immediately after `EvaluateReport` whenever `len(policyResult.ScanUnavailable) > 0`. Do not call it only from `ActionRetryLater`; `SCAN_UNAVAILABLE` and `scan_error_mode_applied_total{mode,path}` must be emitted for applied modes `retry_later`, `block`, and `fail_open`.

- [ ] **Step 4: Update UI audit filters**

Modify `ui/src/pages/AuditLog.tsx`:

```tsx
const EVENT_TYPES = [
  '',
  'SERVED',
  'BLOCKED',
  'QUARANTINED',
  'SCAN_UNAVAILABLE',
  'RELEASED',
  'SCANNED',
  'ALLOWED_WITH_WARNING',
]

const eventTypeBadge: Record<string, string> = {
  SERVED: 'bg-green-100 text-green-800',
  BLOCKED: 'bg-red-100 text-red-800',
  QUARANTINED: 'bg-orange-100 text-orange-800',
  SCAN_UNAVAILABLE: 'bg-red-100 text-red-900',
  RELEASED: 'bg-blue-100 text-blue-800',
  SCANNED: 'bg-gray-100 text-gray-700',
  ALLOWED_WITH_WARNING: 'bg-amber-100 text-amber-800',
}
```

- [ ] **Step 5: Update OpenAPI event enums**

In `docs/api/openapi.yaml`, add `SCAN_UNAVAILABLE` to both audit event enum lists found near:

```yaml
enum: [SERVED, BLOCKED, QUARANTINED, SCAN_UNAVAILABLE, RELEASED, SCANNED, OVERRIDE_CREATED, OVERRIDE_REVOKED, TAG_MUTATED, RESCAN_QUEUED, ALLOWED_WITH_WARNING, INTEGRITY_VIOLATION, ARTIFACT_DELETED]
```

and:

```yaml
enum: [SERVED, BLOCKED, QUARANTINED, SCAN_UNAVAILABLE, RELEASED, SCANNED, OVERRIDE_CREATED, OVERRIDE_REVOKED, TAG_MUTATED, RESCAN_QUEUED, ALLOWED_WITH_WARNING]
```

- [ ] **Step 6: Run focused tests/builds**

Run:

```bash
go test ./internal/config ./internal/adapter -run 'Audit|Warning|JSON|License' -count=1
npm --prefix ui run build
```

Expected: Go tests PASS. UI build PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/model/audit.go internal/config/config.go internal/adapter/base.go internal/adapter/metrics.go ui/src/pages/AuditLog.tsx docs/api/openapi.yaml
git commit -m "feat: audit scanner unavailability"
```

---

### Task 6: Pull Adapter Retry-Later Semantics

**Files:**
- Modify: `internal/adapter/pypi/pypi.go`
- Modify: `internal/adapter/npm/npm.go`
- Modify: `internal/adapter/nuget/nuget.go`
- Modify: `internal/adapter/maven/maven.go`
- Modify: `internal/adapter/rubygems/rubygems.go`
- Modify: `internal/adapter/gomod/gomod.go`
- Modify: `internal/adapter/docker/docker.go`
- Modify: `internal/adapter/pypi/pypi_test.go`

- [ ] **Step 1: Add representative failing PyPI pull test**

Modify `internal/adapter/pypi/pypi_test.go` to allow a custom scan engine/policy engine:

```go
func setupTestPyPIWithEngines(
	t *testing.T,
	upstreamHandler http.HandlerFunc,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
) (*pypi.PyPIAdapter, *httptest.Server, *config.GateDB) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	a := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{})
	a.SetFilesHost(upstream.URL)
	return a, upstream, db
}
```

Keep existing `setupTestPyPI` by calling the new helper with clean engines.

Add this local scanner stub to `internal/adapter/pypi/pypi_test.go`:

```go
type pypiTestScanner struct {
	name       string
	ecosystems []scanner.Ecosystem
	scanFn     func(context.Context, scanner.Artifact) (scanner.ScanResult, error)
}

func (m *pypiTestScanner) Name() string { return m.name }
func (m *pypiTestScanner) Version() string { return "test" }
func (m *pypiTestScanner) SupportedEcosystems() []scanner.Ecosystem { return m.ecosystems }
func (m *pypiTestScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	return m.scanFn(ctx, artifact)
}
func (m *pypiTestScanner) HealthCheck(context.Context) error { return nil }
```

Add helper and tests:

```go
func setupPyPIRequiredScannerError(
	t *testing.T,
	mode policy.ScanErrorMode,
) (*pypi.PyPIAdapter, *config.GateDB) {
	t.Helper()
	fileContent := []byte("fake tarball content")
	required := &pypiTestScanner{
		name:       "guarddog",
		ecosystems: []scanner.Ecosystem{scanner.EcosystemPyPI},
		scanFn: func(_ context.Context, _ scanner.Artifact) (scanner.ScanResult, error) {
			return scanner.ScanResult{}, scanner.NewScanError(scanner.ErrKindOverload, errors.New("bridge overloaded"))
		},
	}
	criticality := map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	scanEngine := scanner.NewEngine(
		[]scanner.Scanner{required},
		time.Second,
		0,
		scanner.WithRetry(1, time.Millisecond),
		scanner.WithCriticality(criticality),
	)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		MinimumConfidence:  0.7,
		OnScanError:        mode,
		ScannerCriticality: criticality,
	}, nil)

	a, _, db := setupTestPyPIWithEngines(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileContent)
	}, scanEngine, policyEngine)
	return a, db
}

func TestPyPIAdapter_RequiredScannerError_Returns503AndDoesNotPersist(t *testing.T) {
	a, db := setupPyPIRequiredScannerError(t, policy.ScanErrorModeQuarantine)
	req := httptest.NewRequest(http.MethodGet, "/packages/re/requests/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM artifact_status`).Scan(&count))
	assert.Equal(t, 0, count)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestPyPIAdapter_RequiredScannerError_BlockModeAuditsScanUnavailable(t *testing.T) {
	a, db := setupPyPIRequiredScannerError(t, policy.ScanErrorModeBlock)
	req := httptest.NewRequest(http.MethodGet, "/packages/re/requests/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestPyPIAdapter_RequiredScannerError_FailOpenModeAuditsScanUnavailable(t *testing.T) {
	a, db := setupPyPIRequiredScannerError(t, policy.ScanErrorModeFailOpen)
	req := httptest.NewRequest(http.MethodGet, "/packages/re/requests/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&count))
	assert.Equal(t, 1, count)
}
```

- [ ] **Step 2: Run PyPI test and verify it fails**

Run:

```bash
go test ./internal/adapter/pypi -run 'TestPyPIAdapter_RequiredScannerError' -count=1
```

Expected: FAIL because adapter still evaluates `[]ScanResult` and serves clean.

- [ ] **Step 3: Update pull adapter scan/policy blocks**

Apply this mechanical shape to all pull sites listed below.

Old shape:

```go
scanResults, err := a.scanEngine.ScanAll(pctx, scanArtifact)
if err != nil {
	log.Error().Err(err).Str("artifact", artifactID).Msg("scan engine error, failing open")
	scanResults = nil
}
policyResult := a.policyEngine.Evaluate(pctx, scanArtifact, scanResults)
```

New shape:

```go
scanReport, err := a.scanEngine.ScanAll(pctx, scanArtifact)
if err != nil {
	log.Error().Err(err).Str("artifact", artifactID).Msg("scan engine error")
}
scanResults := scanReport.Results
policyResult := a.policyEngine.EvaluateReport(pctx, scanArtifact, scanReport)
if len(policyResult.ScanUnavailable) > 0 {
	adapter.AuditScanUnavailable(r.Context(), a.db, policyResult, artifactID, "pull", r.RemoteAddr, r.UserAgent())
}
```

Confirm each adapter's local control flow before editing; the current pull adapters use `switch policyResult.Action`, but avoid blind find/replace if a surrounding block has diverged. Add this switch case before block/quarantine/allow cases:

```go
case policy.ActionRetryLater:
	adapter.WriteRetryLater(w, artifactID, policyResult.Reason, a.policyEngine.RetryAfter())
	return
```

Update all calls that persist, cache, write SBOMs, or trigger async scans to use `scanResults`, which is `scanReport.Results`.

Touch these pull sites:

```text
internal/adapter/pypi/pypi.go
internal/adapter/npm/npm.go
internal/adapter/nuget/nuget.go
internal/adapter/maven/maven.go
internal/adapter/rubygems/rubygems.go
internal/adapter/gomod/gomod.go
internal/adapter/docker/docker.go
```

- [ ] **Step 4: Run focused adapter tests**

Run:

```bash
go test ./internal/adapter/pypi ./internal/adapter/npm ./internal/adapter/nuget ./internal/adapter/maven ./internal/adapter/rubygems ./internal/adapter/gomod ./internal/adapter/docker -run 'RequiredScannerError|PackageDownload|CleanPackage|Manifest' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/pypi/pypi.go internal/adapter/npm/npm.go internal/adapter/nuget/nuget.go internal/adapter/maven/maven.go internal/adapter/rubygems/rubygems.go internal/adapter/gomod/gomod.go internal/adapter/docker/docker.go internal/adapter/pypi/pypi_test.go internal/policy/engine.go
git commit -m "feat: return retry later on pull scanner failures"
```

---

### Task 7: Docker Push and Sync Semantics

**Files:**
- Modify: `internal/adapter/docker/docker.go`
- Modify: `internal/adapter/docker/sync.go`
- Modify: `internal/adapter/docker/push_test.go`
- Modify: `internal/adapter/docker/sync_test.go`

- [ ] **Step 1: Add Docker push failing test**

In `internal/adapter/docker/push_test.go`, add:

```go
type dockerTestScanner struct {
	name       string
	ecosystems []scanner.Ecosystem
	scanFn     func(context.Context, scanner.Artifact) (scanner.ScanResult, error)
}

func (m *dockerTestScanner) Name() string { return m.name }
func (m *dockerTestScanner) Version() string { return "test" }
func (m *dockerTestScanner) SupportedEcosystems() []scanner.Ecosystem { return m.ecosystems }
func (m *dockerTestScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	return m.scanFn(ctx, artifact)
}
func (m *dockerTestScanner) HealthCheck(context.Context) error { return nil }

func setupTestDockerWithPushAndEngines(
	t *testing.T,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
) (*docker.DockerAdapter, *config.GateDB) {
	t.Helper()

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: "https://ghcr.io"},
		},
		Push: config.DockerPushConfig{Enabled: true},
	}
	blobBackend, err := local.NewLocalCacheStore(t.TempDir(), 0)
	require.NoError(t, err)
	blobStore := docker.NewBlobStore(blobBackend, "docker-push")
	return docker.NewDockerAdapterWithPush(db, cacheStore, scanEngine, policyEngine, cfg, blobStore), db
}
```

Then add:

```go
func TestDockerPush_RequiredScannerError_RejectsManifest(t *testing.T) {
	required := &dockerTestScanner{
		name:       "guarddog",
		ecosystems: []scanner.Ecosystem{scanner.EcosystemDocker},
		scanFn: func(_ context.Context, _ scanner.Artifact) (scanner.ScanResult, error) {
			return scanner.ScanResult{}, scanner.NewScanError(scanner.ErrKindRetryable, errors.New("bridge down"))
		},
	}
	criticality := map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	scanEngine := scanner.NewEngine(
		[]scanner.Scanner{required},
		time.Second,
		0,
		scanner.WithRetry(1, time.Millisecond),
		scanner.WithCriticality(criticality),
	)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		OnScanError:        policy.ScanErrorModeQuarantine,
		ScannerCriticality: criticality,
	}, nil)
	a, db := setupTestDockerWithPushAndEngines(t, scanEngine, policyEngine)

	manifestBody := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`)
	req := httptest.NewRequest(http.MethodPut, "/v2/myteam/myapp/manifests/v1.0", bytes.NewReader(manifestBody))
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM artifact_status WHERE status = 'CLEAN'`).Scan(&count))
	assert.Equal(t, 0, count)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM docker_tags WHERE tag = 'v1.0'`).Scan(&count))
	assert.Equal(t, 0, count)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&count))
	assert.Equal(t, 1, count)
}
```

- [ ] **Step 2: Add Docker sync failing tests**

In `internal/adapter/docker/sync_test.go`, add:

```go
func TestSyncService_RequiredScannerError_DoesNotPersistClean(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	manifest := []byte(`{"schemaVersion":2,"config":{"digest":"sha256:newdigest"}}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(manifest)
	}))
	defer ts.Close()

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "latest", "sha256:old", ""))

	required := &dockerTestScanner{
		name:       "guarddog",
		ecosystems: []scanner.Ecosystem{scanner.EcosystemDocker},
		scanFn: func(_ context.Context, _ scanner.Artifact) (scanner.ScanResult, error) {
			return scanner.ScanResult{}, scanner.NewScanError(scanner.ErrKindRetryable, errors.New("bridge down"))
		},
	}
	criticality := map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	scanEngine := scanner.NewEngine([]scanner.Scanner{required}, time.Second, 0, scanner.WithRetry(1, time.Millisecond), scanner.WithCriticality(criticality))
	policyEngine := policy.NewEngine(policy.EngineConfig{OnScanError: policy.ScanErrorModeQuarantine, ScannerCriticality: criticality}, db)

	resolver := docker.NewRegistryResolver(config.DockerUpstreamConfig{DefaultRegistry: ts.URL})
	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, config.DockerSyncConfig{Enabled: true, Interval: "100ms", MaxConcurrent: 1})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	go svc.Start(ctx)
	<-ctx.Done()

	var cleanCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM artifact_status WHERE status = 'CLEAN'`).Scan(&cleanCount))
	assert.Equal(t, 0, cleanCount)
	var auditCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&auditCount))
	assert.Equal(t, 1, auditCount)
}

func TestSyncService_ActionBlock_DoesNotPersistClean(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	manifest := []byte(`{"schemaVersion":2,"config":{"digest":"sha256:newdigest"}}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(manifest)
	}))
	defer ts.Close()

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "latest", "sha256:old", ""))

	required := &dockerTestScanner{
		name:       "guarddog",
		ecosystems: []scanner.Ecosystem{scanner.EcosystemDocker},
		scanFn: func(_ context.Context, _ scanner.Artifact) (scanner.ScanResult, error) {
			return scanner.ScanResult{}, scanner.NewScanError(scanner.ErrKindRetryable, errors.New("bridge down"))
		},
	}
	criticality := map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	scanEngine := scanner.NewEngine([]scanner.Scanner{required}, time.Second, 0, scanner.WithRetry(1, time.Millisecond), scanner.WithCriticality(criticality))
	policyEngine := policy.NewEngine(policy.EngineConfig{OnScanError: policy.ScanErrorModeBlock, ScannerCriticality: criticality}, db)

	resolver := docker.NewRegistryResolver(config.DockerUpstreamConfig{DefaultRegistry: ts.URL})
	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, config.DockerSyncConfig{Enabled: true, Interval: "100ms", MaxConcurrent: 1})

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	go svc.Start(ctx)
	<-ctx.Done()

	var cleanCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM artifact_status WHERE status = 'CLEAN'`).Scan(&cleanCount))
	assert.Equal(t, 0, cleanCount)
	var auditCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&auditCount))
	assert.Equal(t, 1, auditCount)
}
```

- [ ] **Step 3: Run Docker tests and verify they fail**

Run:

```bash
go test ./internal/adapter/docker -run 'RequiredScannerError|ActionBlock_DoesNotPersistClean' -count=1
```

Expected: FAIL because push/sync still use fail-open behavior and sync still maps `ActionBlock` to clean.

- [ ] **Step 4: Update Docker push**

In `internal/adapter/docker/docker.go` push path:

```go
scanReport, scanErr := a.scanEngine.ScanAll(pctx, scanArtifact)
if scanErr != nil {
	log.Error().Err(scanErr).Str("artifact", artifactID).Msg("docker push: scan engine error")
}
scanResults := scanReport.Results
policyResult := a.policyEng.EvaluateReport(pctx, scanArtifact, scanReport)
if len(policyResult.ScanUnavailable) > 0 {
	adapter.AuditScanUnavailable(r.Context(), a.db, policyResult, artifactID, "push", r.RemoteAddr, r.UserAgent())
}
```

Add switch case:

```go
case policy.ActionRetryLater:
	adapter.WriteJSONError(w, http.StatusServiceUnavailable, adapter.ErrorResponse{
		Error:    "scanner unavailable",
		Artifact: artifactID,
		Reason:   policyResult.Reason,
	})
	return
```

Ensure this case returns before `persistArtifact`, `UpsertTag`, or `recordManifestBlobRefs`.

- [ ] **Step 5: Update Docker sync**

In `internal/adapter/docker/sync.go`:

```go
scanReport, scanErr := s.scanEngine.ScanAll(ctx, scanArtifact)
if scanErr != nil {
	log.Error().Err(scanErr).Str("artifact", artifactID).Msg("docker sync: scan engine error")
}
scanResults := scanReport.Results
policyResult := s.policyEng.EvaluateReport(ctx, scanArtifact, scanReport)
if len(policyResult.ScanUnavailable) > 0 {
	adapter.AuditScanUnavailable(ctx, s.db, policyResult, artifactID, "sync", "", "")
}
```

Replace the switch with explicit non-clean handling:

```go
switch policyResult.Action {
case policy.ActionRetryLater:
	return
case policy.ActionBlock:
	_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
		EventType:  model.EventBlocked,
		ArtifactID: artifactID,
		Reason:     policyResult.Reason,
	})
	return
case policy.ActionQuarantine:
	now := time.Now().UTC()
	_ = s.persistArtifact(artifactID, scanArtifact, manifestSHA, manifestBytes,
		model.StatusQuarantined, policyResult.Reason, &now, scanResults)
	_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
		EventType:  model.EventQuarantined,
		ArtifactID: artifactID,
		Reason:     policyResult.Reason,
	})
case policy.ActionAllowWithWarning:
	_ = s.persistArtifact(artifactID, scanArtifact, manifestSHA, manifestBytes,
		model.StatusClean, "", nil, scanResults)
	_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
		EventType:  model.EventAllowedWithWarning,
		ArtifactID: artifactID,
		Reason:     policyResult.Reason,
	})
case policy.ActionAllow:
	_ = s.persistArtifact(artifactID, scanArtifact, manifestSHA, manifestBytes,
		model.StatusClean, "", nil, scanResults)
default:
	return
}
```

Move tag update and cache write under an allow-only guard:

```go
if policyResult.Action == policy.ActionAllow || policyResult.Action == policy.ActionAllowWithWarning {
	if digestChanged {
		artIDPtr := artifactID
		_ = UpsertTag(s.db, repo.ID, tag.Tag, upstreamDigest, artIDPtr)
	}

	if s.cache != nil {
		cacheTmp, err := writeManifestToTemp(manifestBytes)
		if err == nil {
			defer os.Remove(cacheTmp)
			cacheArtifact := scanner.Artifact{
				ID:        artifactID,
				Ecosystem: scanner.EcosystemDocker,
				Name:      safeName,
				Version:   tag.Tag,
				LocalPath: cacheTmp,
				SHA256:    manifestSHA,
				SizeBytes: int64(len(manifestBytes)),
			}
			_ = s.cache.Put(ctx, cacheArtifact, cacheTmp)
		}
	}
}
```

This prevents `ActionBlock` and `ActionRetryLater` from becoming clean or servable.

- [ ] **Step 6: Run Docker tests**

Run:

```bash
go test ./internal/adapter/docker -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/adapter/docker/docker.go internal/adapter/docker/sync.go internal/adapter/docker/push_test.go internal/adapter/docker/sync_test.go
git commit -m "feat: fail closed on docker scanner failures"
```

---

### Task 8: UNKNOWN Verdicts Become Scanner Errors

**Files:**
- Modify: `internal/scanner/ai/scanner.go`
- Modify: `internal/scanner/ai/scanner_test.go`
- Modify: `internal/scanner/versiondiff/scanner.go`
- Modify: `internal/scanner/versiondiff/scanner_test.go`

- [ ] **Step 1: Update AI scanner tests**

In `internal/scanner/ai/scanner_test.go`, replace `TestAIScanner_UnknownVerdict_FailsOpen` with:

```go
func TestAIScanner_UnknownVerdict_ReturnsRetryableScanError(t *testing.T) {
	s, cleanup := newTestAIScanner(t, "UNKNOWN")
	defer cleanup()

	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pypi:pkg:1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "pkg",
		Version:   "1.0.0",
	})

	require.Error(t, err)
	var scanErr *scanner.ScanError
	require.ErrorAs(t, err, &scanErr)
	assert.Equal(t, scanner.ErrKindRetryable, scanErr.Kind)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Equal(t, err, result.Error)
}
```

Update verdict mapping table:

```go
{"UNKNOWN", scanner.VerdictClean, true},
{"", scanner.VerdictClean, true},
```

- [ ] **Step 2: Update version-diff scanner tests**

In `internal/scanner/versiondiff/scanner_test.go`, add or update the UNKNOWN test:

```go
func TestVersionDiffScanner_UnknownVerdict_ReturnsRetryableScanError(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{Verdict: "UNKNOWN", Confidence: 0.0}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})

	require.Error(t, err)
	var scanErr *scanner.ScanError
	require.ErrorAs(t, err, &scanErr)
	assert.Equal(t, scanner.ErrKindRetryable, scanErr.Kind)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Equal(t, err, res.Error)

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM version_diff_results"))
	assert.Equal(t, 0, n, "UNKNOWN must NOT persist")
}
```

- [ ] **Step 3: Run scanner tests and verify they fail**

Run:

```bash
go test ./internal/scanner/ai ./internal/scanner/versiondiff -run 'UnknownVerdict|UNKNOWN' -count=1
```

Expected: FAIL because UNKNOWN still maps to clean without an error.

- [ ] **Step 4: Change AI verdict mapping**

Modify `internal/scanner/ai/scanner.go`:

```go
verdict, verdictErr := mapVerdict(resp.Verdict)
result := scanner.ScanResult{
	Verdict:    verdict,
	Confidence: resp.Confidence,
	ScannerID:  s.Name(),
	ScannedAt:  time.Now(),
	Error:      verdictErr,
}
if verdictErr != nil {
	return result, verdictErr
}
```

Change `mapVerdict`:

```go
func mapVerdict(v string) (scanner.Verdict, error) {
	switch v {
	case "MALICIOUS":
		return scanner.VerdictMalicious, nil
	case "SUSPICIOUS":
		return scanner.VerdictSuspicious, nil
	case "CLEAN":
		return scanner.VerdictClean, nil
	default:
		return scanner.VerdictClean, scanner.NewScanError(scanner.ErrKindRetryable, fmt.Errorf("ai scanner returned unknown verdict %q", v))
	}
}
```

Also change exhausted bridge retries to return the error:

```go
scanErr := scanner.NewScanError(scanner.ErrKindRetryable, fmt.Errorf("ai scanner: %s: %w", artifact.ID, err))
return scanner.ScanResult{
	Verdict:    scanner.VerdictClean,
	Confidence: 0,
	ScannerID:  s.Name(),
	ScannedAt:  time.Now(),
	Error:      scanErr,
}, scanErr
```

- [ ] **Step 5: Change version-diff UNKNOWN mapping**

Modify `verdictMapping` in `internal/scanner/versiondiff/scanner.go`:

```go
scanErr *scanner.ScanError
```

In UNKNOWN/default:

```go
mp.originalVerdict = scanner.VerdictClean
mp.finalVerdict = scanner.VerdictClean
mp.persistRow = false
mp.scanErr = scanner.NewScanError(scanner.ErrKindRetryable, fmt.Errorf("version-diff returned unknown verdict %q", resp.Verdict))
```

After `mapping := s.mapVerdict(resp)` and before persistence:

```go
if mapping.scanErr != nil {
	return scanner.ScanResult{
		Verdict:        scanner.VerdictClean,
		Confidence:     0,
		ScannerID:      scannerName,
		ScannerVersion: scannerVersion,
		Duration:       time.Since(start),
		ScannedAt:      start,
		Error:          mapping.scanErr,
	}, mapping.scanErr
}
```

- [ ] **Step 6: Run scanner tests**

Run:

```bash
go test ./internal/scanner/ai ./internal/scanner/versiondiff -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/scanner/ai/scanner.go internal/scanner/ai/scanner_test.go internal/scanner/versiondiff/scanner.go internal/scanner/versiondiff/scanner_test.go
git commit -m "feat: treat unknown scanner verdicts as errors"
```

---

### Task 9: Full Compile Sweep for `ScanAll` API Migration

**Files:**
- Modify: `internal/scheduler/rescan.go`
- Modify: stale `ScanAll` callers reported by `go test ./internal/... ./cmd/... -count=1`

- [ ] **Step 1: Run package tests to find stale `ScanAll` callers**

Run:

```bash
go test ./internal/... ./cmd/... -count=1
```

Expected before fixes: compile errors can remain where callers still expect `[]scanner.ScanResult`.

- [ ] **Step 2: Fix stale call sites**

For every compile error shaped like:

```text
cannot use scanReport (variable of struct type scanner.ScanReport) as []scanner.ScanResult
```

Use this exact conversion:

```go
scanReport, err := scanEngine.ScanAll(ctx, artifact, excludeNames...)
if err != nil {
	log.Error().Err(err).Str("artifact", artifact.ID).Msg("scan engine error")
}
scanResults := scanReport.Results
policyResult := policyEngine.EvaluateReport(ctx, artifact, scanReport)
```

For rescan scheduler calls in `internal/scheduler/rescan.go`, keep the existing `ai-scanner` exclude:

```go
scanReport, err := r.scanEngine.ScanAll(ctx, artifact, "ai-scanner")
scanResults := scanReport.Results
```

Do not add special handling for excluded required scanners. The engine ignores such excludes by construction.

- [ ] **Step 3: Run compile sweep again**

Run:

```bash
go test ./internal/... ./cmd/... -count=1
```

Expected: PASS, or only unrelated pre-existing integration/environment failures. If failures are unrelated, capture exact package/test names for the final handoff.

- [ ] **Step 4: Commit**

```bash
git add internal cmd
git commit -m "chore: migrate scan report call sites"
```

---

### Task 10: Documentation and ADR

**Files:**
- Modify: `docs/policy.md`
- Modify: `docs/scanners.md`
- Modify: `docs/architecture.md`
- Modify: `CLAUDE.md`
- Create: `docs/adr/ADR-011-fail-closed-scanner-errors.md`

- [ ] **Step 1: Update scanner docs**

In `docs/scanners.md`, replace fail-open scanner language with:

```markdown
Inline scanner failures are reported in `scanner.ScanReport.Errored`. Required scanners fail closed according to `policy.on_scan_error`; best-effort scanner failures are logged and counted but do not block artifact serving by themselves.
```

Document criticality keys:

```markdown
Criticality is keyed by scanner `Name()`:

- `builtin-threat-feed`
- `hash-verifier`
- `install-hook-analyzer`
- `obfuscation-detector`
- `exfil-detector`
- `pth-inspector`
- `builtin-typosquat`
- `guarddog`
- `ai-scanner`
- `version-diff`
- `builtin-reputation`
- `trivy`
- `osv`
```

- [ ] **Step 2: Update policy docs**

In `docs/policy.md`, add:

```markdown
### Scanner Failure Policy

`policy.on_scan_error` controls required scanner failures:

- `quarantine` (default): pull requests receive HTTP 503 with `Retry-After`, Docker pushes are rejected with 5xx, and Docker sync skips the artifact.
- `block`: policy returns a block decision. Pull/push requests are rejected and Docker sync does not mark the artifact clean.
- `fail_open`: preserves legacy availability behavior, but emits `SCAN_UNAVAILABLE` audit events and Prometheus metrics.

Explicit allow overrides and static allowlist entries bypass scanner availability checks. Deny overrides still block.
```

- [ ] **Step 3: Update architecture and CLAUDE**

Replace `CLAUDE.md` line that says scanner failures fail open with:

```markdown
- Required scanner failures fail closed according to `policy.on_scan_error`; `fail_open` is an explicit operator escape hatch and must emit `SCAN_UNAVAILABLE`.
```

Replace `docs/architecture.md` fail-open statements with:

```markdown
Scanner errors are explicit in `ScanReport`. Required scanner errors are handled by policy before verdict aggregation.
```

- [ ] **Step 4: Add ADR**

Create `docs/adr/ADR-011-fail-closed-scanner-errors.md`:

```markdown
# ADR-011: Fail Closed on Required Inline Scanner Errors

Date: 2026-06-17

## Status

Accepted

## Context

Inline scanner failures previously degraded to clean verdicts, allowing artifacts to be served unscanned during scanner outages or overload.

## Decision

Inline scan completeness is explicit through `scanner.ScanReport`. Scanners configured as `required` must produce a verdict before an artifact can become servable, unless `policy.on_scan_error` is explicitly set to `fail_open`.

Pull paths return HTTP 503 with `Retry-After`, Docker push rejects the upload, and Docker sync skips the artifact. The error path persists no clean status and writes no cache entry.

## Consequences

Scanner outages can temporarily reduce availability for artifacts that require scanner coverage. Operators can temporarily choose `fail_open`, but this emits `SCAN_UNAVAILABLE` audit events and metrics.
```

- [ ] **Step 5: Run doc consistency search**

Run:

```bash
rg -n "fail-open|failing open|fails open|VerdictClean.*error|Scanner errors" CLAUDE.md docs internal/scanner internal/policy
```

Expected: no stale claim that required inline scanner failures silently allow artifacts. Best-effort or explicit `fail_open` references are okay.

- [ ] **Step 6: Commit**

```bash
git add docs/policy.md docs/scanners.md docs/architecture.md CLAUDE.md docs/adr/ADR-011-fail-closed-scanner-errors.md
git commit -m "docs: record fail-closed scanner policy"
```

---

### Task 11: Final Verification

**Files:**
- No new files unless verification exposes a bug.

- [ ] **Step 1: Go tests**

Run:

```bash
go test ./internal/... ./cmd/... -count=1
```

Expected: PASS.

- [ ] **Step 2: UI build**

Run:

```bash
npm --prefix ui run build
```

Expected: PASS.

- [ ] **Step 3: Focused regression tests**

Run:

```bash
go test ./internal/scanner ./internal/policy ./internal/config ./internal/adapter/pypi ./internal/adapter/docker ./cmd/shieldoo-gate -run 'ScanError|ScanAll|RequiredScannerError|ScannerCriticality|UnknownVerdict|ActionBlock_DoesNotPersistClean' -count=1
```

Expected: PASS.

- [ ] **Step 4: Invariant search**

Run:

```bash
rg -n "scanResults\\s*=\\s*nil|failing open|Evaluate\\(.*scanResults|ScanAll\\(" internal/adapter internal/scheduler internal/api
```

Expected:
- No `scanResults = nil` fail-open handling in serving/push/sync paths.
- `EvaluateReport` used for fresh scan paths.
- Remaining `Evaluate(...)` calls are cache/license-only or legacy tests that intentionally pass stored results.

- [ ] **Step 5: Commit verification cleanup**

```bash
git add .
git commit -m "test: verify fail-closed scanner errors"
```

Skip this commit when Step 1-4 do not require code or test fixes.

---

## Self-Review Checklist

- Spec coverage:
  - Pull paths return 503 + Retry-After on required scanner unavailable.
  - Docker push rejects the upload and does not create a servable tag.
  - Docker sync skips `ActionRetryLater` and `ActionBlock`; neither can persist clean.
  - Required scanner excludes are ignored by the engine.
  - Best-effort excludes are recorded in `ScanReport.Skipped`.
  - Unknown criticality values fail config validation.
  - Missing required scanners fail startup unless `policy.on_scan_error=fail_open`.
  - `SCAN_UNAVAILABLE` event is registered in model, alert allow-list, UI, and OpenAPI.
  - `SCAN_UNAVAILABLE` and `scan_error_mode_applied_total` are emitted for required-scanner failures in applied modes `retry_later`, `block`, and `fail_open`.
  - License early returns preserve `PolicyResult.ScanUnavailable` so scanner outages are audited even when license policy blocks first.
  - Adapter regression tests assert `SCAN_UNAVAILABLE` for retry-later, block, and fail-open behavior.
  - UNKNOWN verdicts become scanner errors instead of clean success.
- Placeholder scan:
  - Marker scan completed.
- Type consistency:
  - Scanner criticality type is `scanner.Criticality`.
  - Policy mode type is `policy.ScanErrorMode`.
  - New policy API is `EvaluateReport`; old `Evaluate` remains as wrapper.
  - Adapter persistence continues to receive `scanReport.Results`.
