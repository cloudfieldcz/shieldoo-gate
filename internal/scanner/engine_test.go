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
	results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Len(t, results, 2)
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
	results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemDocker})
	require.NoError(t, err)
	assert.Len(t, results, 0)
}

func TestEngine_ScanAll_Timeout_ReturnsErrorNotMalicious(t *testing.T) {
	slow := &mockScanner{
		name:       "slow",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(ctx context.Context, _ Artifact) (ScanResult, error) {
			select {
			case <-ctx.Done():
				return ScanResult{}, ctx.Err()
			case <-time.After(5 * time.Second):
				return ScanResult{Verdict: VerdictClean}, nil
			}
		},
	}

	engine := NewEngine([]Scanner{slow}, 50*time.Millisecond, 0)
	results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, VerdictClean, results[0].Verdict)
	assert.NotNil(t, results[0].Error)
}

func TestEngine_ScanAll_ScannerError_FailsOpen(t *testing.T) {
	failing := &mockScanner{
		name:       "failing",
		ecosystems: []Ecosystem{EcosystemPyPI},
		scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
			return ScanResult{}, errors.New("scanner crashed")
		},
	}

	engine := NewEngine([]Scanner{failing}, 30*time.Second, 0)
	results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, VerdictClean, results[0].Verdict)
	assert.NotNil(t, results[0].Error)
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
