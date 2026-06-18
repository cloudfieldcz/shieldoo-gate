package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockScanner struct {
	name       string
	ecosystems []Ecosystem
	scanFn     func(ctx context.Context, artifact Artifact) (ScanResult, error)
	healthFn   func(ctx context.Context) error
}

func (m *mockScanner) Name() string                     { return m.name }
func (m *mockScanner) Version() string                  { return "1.0.0-test" }
func (m *mockScanner) SupportedEcosystems() []Ecosystem { return m.ecosystems }
func (m *mockScanner) Scan(ctx context.Context, a Artifact) (ScanResult, error) {
	return m.scanFn(ctx, a)
}
func (m *mockScanner) HealthCheck(ctx context.Context) error {
	if m.healthFn != nil {
		return m.healthFn(ctx)
	}
	return nil
}

func TestEngine_ScanAll_RunsAllMatchingScanners(t *testing.T) {
	s1 := &mockScanner{
		name:       "scanner1",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			return ScanResult{Verdict: VerdictClean, Confidence: 1.0, ScannerID: "scanner1"}, nil
		},
	}
	s2 := &mockScanner{
		name:       "scanner2",
		ecosystems: []Ecosystem{EcosystemPyPI, EcosystemNPM},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			return ScanResult{Verdict: VerdictSuspicious, Confidence: 0.8, ScannerID: "scanner2"}, nil
		},
	}

	engine := NewEngine([]Scanner{s1, s2}, 30*time.Second, 0)
	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Len(t, report.Results, 2)
}

func TestEngine_ScanAll_FiltersUnsupportedEcosystem(t *testing.T) {
	s := &mockScanner{
		name:       "pypi-only",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			return ScanResult{Verdict: VerdictClean}, nil
		},
	}

	engine := NewEngine([]Scanner{s}, 30*time.Second, 0)
	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemDocker})
	require.NoError(t, err)
	assert.Len(t, report.Results, 0)
}

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

func TestEngine_ScanAll_TerminalErrorsDoNotOpenCircuitBreaker(t *testing.T) {
	// A terminal error is a per-artifact permanent condition (e.g. oversized),
	// not scanner-health degradation. Many terminal errors in a row must NOT open
	// the per-scanner breaker, otherwise a burst of oversized artifacts would
	// fail unrelated, normal artifacts as overload until cooldown. The scanner is
	// marked REQUIRED so its breaker is actually consulted (the breaker applies
	// only to required scanners); the breaker threshold is 5, so we scan well past
	// it and assert every call still reaches the scanner, still classifies as
	// terminal (never overload from an open circuit), and leaves the breaker shut.
	attempts := 0
	oversized := &mockScanner{
		name:       "version-diff",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			attempts++
			return ScanResult{}, NewScanError(ErrKindTerminal, errors.New("artifact exceeds max size"))
		},
	}

	engine := NewEngine(
		[]Scanner{oversized},
		time.Second,
		0,
		WithCriticality(map[string]Criticality{"version-diff": CriticalityRequired}),
	)

	const scans = 8 // > breaker threshold (5)
	for i := 0; i < scans; i++ {
		report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
		require.NoError(t, err)
		require.Contains(t, report.Errored, "version-diff")
		assert.Equal(t, ErrKindTerminal, report.Errored["version-diff"].Kind,
			"scan %d: terminal must stay terminal, never become overload from an open circuit", i)
	}
	assert.Equal(t, scans, attempts, "breaker must never short-circuit terminal-only scanners")
	assert.False(t, engine.breakers["version-diff"].isOpen(), "terminal errors must not open the breaker")
}

func TestEngine_ScanAll_ThrottleErrorsDoNotOpenCircuitBreaker(t *testing.T) {
	// A throttle error is intentional local backpressure on ONE package (the
	// version-diff per-package rate limit), not scanner-health degradation. A hot
	// package hammering its quota must NOT open the scanner-wide breaker and fail
	// unrelated, healthy packages as overload. The scanner is marked REQUIRED so
	// its breaker is actually consulted (the breaker applies only to required
	// scanners); the breaker threshold is 5, so we scan well past it and assert
	// every call still reaches the scanner, still classifies as throttled (never
	// overload from an open circuit), and leaves the breaker shut.
	attempts := 0
	throttled := &mockScanner{
		name:       "version-diff",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			attempts++
			return ScanResult{}, NewScanError(ErrKindThrottled, errors.New("rate-limited"))
		},
	}

	engine := NewEngine(
		[]Scanner{throttled},
		time.Second,
		0,
		WithCriticality(map[string]Criticality{"version-diff": CriticalityRequired}),
	)

	const scans = 8 // > breaker threshold (5)
	for i := 0; i < scans; i++ {
		report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
		require.NoError(t, err)
		require.Contains(t, report.Errored, "version-diff")
		assert.Equal(t, ErrKindThrottled, report.Errored["version-diff"].Kind,
			"scan %d: throttle must stay throttled, never become overload from an open circuit", i)
	}
	assert.Equal(t, scans, attempts, "breaker must never short-circuit a throttled scanner")
	assert.False(t, engine.breakers["version-diff"].isOpen(), "throttled errors must not open the breaker")
}

func TestEngine_ScanAll_RetryableErrorsStillOpenCircuitBreaker(t *testing.T) {
	// Counterpart to the terminal/throttle tests: retryable errors DO indicate
	// scanner-health degradation, so a run of them on a REQUIRED scanner must
	// actually accumulate and open the breaker (this exercises the live counting
	// path, unlike TestEngine_ScanAll_RequiredScannerCircuitBreaks which forces
	// the breaker open by hand). After the threshold (5) consecutive failures the
	// scanner is short-circuited and stops being called, with the error reported
	// as overload (circuit open).
	attempts := 0
	flaky := &mockScanner{
		name:       "guarddog",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			attempts++
			return ScanResult{}, NewScanError(ErrKindRetryable, errors.New("bridge crashed"))
		},
	}

	engine := NewEngine(
		[]Scanner{flaky},
		time.Second,
		0,
		WithCriticality(map[string]Criticality{"guarddog": CriticalityRequired}),
	)

	var lastKind ScanErrorKind
	for i := 0; i < 8; i++ {
		report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
		require.NoError(t, err)
		require.Contains(t, report.Errored, "guarddog")
		lastKind = report.Errored["guarddog"].Kind
	}
	assert.Less(t, attempts, 8, "breaker should short-circuit the scanner after the failure threshold")
	assert.Equal(t, ErrKindOverload, lastKind, "open circuit must surface as overload")
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

func TestEngine_HealthCheck_RunsScannersInParallel(t *testing.T) {
	// Three scanners that each sleep 100ms. Sequential execution would take
	// 300ms; parallel should finish in ~100ms. We bound the total at 200ms
	// (well under sum, well over individual) to detect any regression to the
	// previous sequential implementation that caused production health check
	// timeouts.
	const perScanner = 100 * time.Millisecond
	makeSlow := func(name string) *mockScanner {
		return &mockScanner{
			name: name,
			healthFn: func(ctx context.Context) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(perScanner):
					return nil
				}
			},
		}
	}

	engine := NewEngine([]Scanner{makeSlow("a"), makeSlow("b"), makeSlow("c")}, time.Second, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	start := time.Now()
	status := engine.HealthCheck(ctx)
	elapsed := time.Since(start)

	require.Len(t, status, 3)
	for name, err := range status {
		assert.NoError(t, err, "scanner %s reported unhealthy under a tight budget that only fits if we run in parallel", name)
	}
	assert.Less(t, elapsed, 2*perScanner, "health check elapsed %v — must run scanners in parallel", elapsed)
}

func TestEngine_HealthCheck_PropagatesPerScannerErrors(t *testing.T) {
	healthy := &mockScanner{name: "healthy"}
	broken := &mockScanner{
		name:     "broken",
		healthFn: func(_ context.Context) error { return errors.New("bridge down") },
	}

	engine := NewEngine([]Scanner{healthy, broken}, time.Second, 0)
	status := engine.HealthCheck(context.Background())

	assert.NoError(t, status["healthy"])
	require.Error(t, status["broken"])
	assert.Contains(t, status["broken"].Error(), "bridge down")
}

// A best-effort scanner must never be short-circuited by its circuit breaker:
// its verdict is fail-open regardless, so skipping it only silently drops the
// data it carries (SBOM, licenses, vuln findings) without any safety benefit.
// Regression guard for the SBOM-loss bug where an open Trivy breaker (tripped
// by a burst of heavy concurrent scans) blacked out Trivy — and thus SBOM
// generation — for unrelated artifacts scanned during the cooldown window.
func TestEngine_ScanAll_BestEffortScannerNotCircuitBroken(t *testing.T) {
	calls := 0
	bestEffort := &mockScanner{
		name:       "trivy", // unlisted in criticality => best_effort
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			calls++
			return ScanResult{Verdict: VerdictClean, ScannerID: "trivy", SBOMContent: []byte("{}")}, nil
		},
	}

	engine := NewEngine([]Scanner{bestEffort}, time.Second, 0)
	// Force the breaker open, as if a prior burst had tripped it.
	for i := 0; i < 10; i++ {
		engine.breakers["trivy"].recordFailure()
	}
	require.True(t, engine.breakers["trivy"].isOpen(), "precondition: breaker must be open")

	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "best-effort scanner must still be invoked when its breaker is open")
	require.Len(t, report.Results, 1, "best-effort result must land in Results, not be dropped")
	assert.NotEmpty(t, report.Results[0].SBOMContent, "SBOM content must survive an open breaker")
	assert.Empty(t, report.Errored)
}

// A required scanner, by contrast, must still fail fast when its breaker is
// open — that is the whole point of fail-closed gating (a quick overload error
// instead of a per-attempt timeout).
func TestEngine_ScanAll_RequiredScannerCircuitBreaks(t *testing.T) {
	calls := 0
	required := &mockScanner{
		name:       "guarddog",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			calls++
			return ScanResult{Verdict: VerdictClean, ScannerID: "guarddog"}, nil
		},
	}

	engine := NewEngine(
		[]Scanner{required},
		time.Second,
		0,
		WithCriticality(map[string]Criticality{"guarddog": CriticalityRequired}),
	)
	for i := 0; i < 10; i++ {
		engine.breakers["guarddog"].recordFailure()
	}
	require.True(t, engine.breakers["guarddog"].isOpen(), "precondition: breaker must be open")

	report, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Equal(t, 0, calls, "required scanner must be short-circuited while its breaker is open")
	require.Contains(t, report.Errored, "guarddog")
	assert.Equal(t, ErrKindOverload, report.Errored["guarddog"].Kind)
	assert.Empty(t, report.Results)
}
