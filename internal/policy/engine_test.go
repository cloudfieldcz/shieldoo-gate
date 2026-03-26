package policy_test

import (
	"context"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultEngineConfig() policy.EngineConfig {
	return policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.5,
	}
}

func pypiArtifact(name, version string) scanner.Artifact {
	return scanner.Artifact{
		ID:        "pypi:" + name + ":" + version,
		Ecosystem: scanner.EcosystemPyPI,
		Name:      name,
		Version:   version,
	}
}

func TestPolicyEngine_MaliciousVerdict_ReturnsBlock(t *testing.T) {
	engine := policy.NewEngine(defaultEngineConfig())
	results := []scanner.ScanResult{
		{ScannerID: "guarddog", Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("evil-pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestPolicyEngine_SuspiciousVerdict_ReturnsQuarantine(t *testing.T) {
	engine := policy.NewEngine(defaultEngineConfig())
	results := []scanner.ScanResult{
		{ScannerID: "osv", Verdict: scanner.VerdictSuspicious, Confidence: 0.8},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("sketchy-pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
}

func TestPolicyEngine_CleanVerdict_ReturnsAllow(t *testing.T) {
	engine := policy.NewEngine(defaultEngineConfig())
	results := []scanner.ScanResult{
		{ScannerID: "trivy", Verdict: scanner.VerdictClean, Confidence: 0.95},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("requests", "2.31.0"), results)
	assert.Equal(t, policy.ActionAllow, result.Action)
}

func TestPolicyEngine_AllowlistOverride_AllowsMalicious(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Allowlist = []string{"pypi:litellm:==1.82.6"}
	engine := policy.NewEngine(cfg)

	results := []scanner.ScanResult{
		{ScannerID: "guarddog", Verdict: scanner.VerdictMalicious, Confidence: 0.99},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("litellm", "1.82.6"), results)
	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Contains(t, result.Reason, "allowlist")
}

func TestPolicyEngine_AllowlistNoMatch_StillBlocks(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Allowlist = []string{"pypi:litellm:==1.82.6"}
	engine := policy.NewEngine(cfg)

	results := []scanner.ScanResult{
		{ScannerID: "guarddog", Verdict: scanner.VerdictMalicious, Confidence: 0.99},
	}
	// Different version — not allowlisted.
	result := engine.Evaluate(context.Background(), pypiArtifact("litellm", "1.82.5"), results)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestParseAllowlistEntry_ValidEntry(t *testing.T) {
	entry, err := policy.ParseAllowlistEntry("pypi:litellm:==1.82.6")
	require.NoError(t, err)
	assert.Equal(t, "pypi", entry.Ecosystem)
	assert.Equal(t, "litellm", entry.Name)
	assert.Equal(t, "1.82.6", entry.Version)
}
