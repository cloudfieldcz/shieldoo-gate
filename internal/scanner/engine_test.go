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

	engine := NewEngine([]Scanner{s1, s2}, 30*time.Second)
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

	engine := NewEngine([]Scanner{s}, 30*time.Second)
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

	engine := NewEngine([]Scanner{slow}, 50*time.Millisecond)
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

	engine := NewEngine([]Scanner{failing}, 30*time.Second)
	results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, VerdictClean, results[0].Verdict)
	assert.NotNil(t, results[0].Error)
}
