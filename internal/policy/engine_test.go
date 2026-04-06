package policy_test

import (
	"context"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func defaultEngineConfig() policy.EngineConfig {
	return policy.EngineConfig{
		Mode:                policy.PolicyModeStrict,
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

func suspiciousResult(scannerID string, severity scanner.Severity) scanner.ScanResult {
	return scanner.ScanResult{
		ScannerID:  scannerID,
		Verdict:    scanner.VerdictSuspicious,
		Confidence: 0.9,
		Findings: []scanner.Finding{
			{Severity: severity, Category: "test-finding", Description: "test"},
		},
	}
}

// --- Existing tests (backward compat with strict mode) ---

func TestPolicyEngine_MaliciousVerdict_ReturnsBlock(t *testing.T) {
	engine := policy.NewEngine(defaultEngineConfig(), nil)
	results := []scanner.ScanResult{
		{ScannerID: "guarddog", Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("evil-pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestPolicyEngine_SuspiciousVerdict_ReturnsQuarantine(t *testing.T) {
	engine := policy.NewEngine(defaultEngineConfig(), nil)
	results := []scanner.ScanResult{
		{ScannerID: "osv", Verdict: scanner.VerdictSuspicious, Confidence: 0.8,
			Findings: []scanner.Finding{{Severity: scanner.SeverityMedium, Category: "CVE"}}},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("sketchy-pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
}

func TestPolicyEngine_CleanVerdict_ReturnsAllow(t *testing.T) {
	engine := policy.NewEngine(defaultEngineConfig(), nil)
	results := []scanner.ScanResult{
		{ScannerID: "trivy", Verdict: scanner.VerdictClean, Confidence: 0.95},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("requests", "2.31.0"), results)
	assert.Equal(t, policy.ActionAllow, result.Action)
}

func TestPolicyEngine_AllowlistOverride_AllowsMalicious(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Allowlist = []string{"pypi:litellm:==1.82.6"}
	engine := policy.NewEngine(cfg, nil)

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
	engine := policy.NewEngine(cfg, nil)

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

// --- evaluateSuspicious mode tests ---

func TestEvaluateSuspicious_StrictMode_AlwaysQuarantine(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModeStrict
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{suspiciousResult("osv", scanner.SeverityMedium)}
	result := engine.Evaluate(context.Background(), pypiArtifact("qs", "6.11.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
	assert.Contains(t, result.Reason, "strict mode")
}

func TestEvaluateSuspicious_PermissiveMode_MediumSeverity_AllowWithWarning(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModePermissive
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{suspiciousResult("osv", scanner.SeverityMedium)}
	result := engine.Evaluate(context.Background(), pypiArtifact("qs", "6.11.0"), results)
	assert.Equal(t, policy.ActionAllowWithWarning, result.Action)
	assert.Contains(t, result.Reason, "permissive mode")
}

func TestEvaluateSuspicious_PermissiveMode_HighSeverity_Quarantine(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModePermissive
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{suspiciousResult("osv", scanner.SeverityHigh)}
	result := engine.Evaluate(context.Background(), pypiArtifact("bad-pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
	assert.Contains(t, result.Reason, "permissive mode")
}

func TestEvaluateSuspicious_BalancedMode_HighSeverity_Quarantine(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModeBalanced
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{suspiciousResult("osv", scanner.SeverityHigh)}
	result := engine.Evaluate(context.Background(), pypiArtifact("bad-pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
	assert.Contains(t, result.Reason, "balanced mode")
}

func TestEvaluateSuspicious_BalancedMode_AITriageDisabled_FallbackQuarantine(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModeBalanced
	cfg.AITriage = config.AITriageConfig{Enabled: false}
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{suspiciousResult("osv", scanner.SeverityMedium)}
	result := engine.Evaluate(context.Background(), pypiArtifact("qs", "6.11.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
	assert.Contains(t, result.Reason, "degraded")
}

func TestEvaluateSuspicious_NoFindings_FallbackQuarantine(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModePermissive
	engine := policy.NewEngine(cfg, nil)

	// SUSPICIOUS without findings — anomaly
	results := []scanner.ScanResult{
		{ScannerID: "osv", Verdict: scanner.VerdictSuspicious, Confidence: 0.9},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("weird", "1.0.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
	assert.Contains(t, result.Reason, "anomaly")
}

// --- Threat-feed invariant across ALL modes ---

func TestThreatFeedMalicious_AlwaysBlocked_StrictMode(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModeStrict
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{
		{ScannerID: "builtin-threat-feed", Verdict: scanner.VerdictMalicious, Confidence: 1.0},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("evil", "1.0.0"), results)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestThreatFeedMalicious_AlwaysBlocked_BalancedMode(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModeBalanced
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{
		{ScannerID: "builtin-threat-feed", Verdict: scanner.VerdictMalicious, Confidence: 1.0},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("evil", "1.0.0"), results)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestThreatFeedMalicious_AlwaysBlocked_PermissiveMode(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModePermissive
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{
		{ScannerID: "builtin-threat-feed", Verdict: scanner.VerdictMalicious, Confidence: 1.0},
	}
	result := engine.Evaluate(context.Background(), pypiArtifact("evil", "1.0.0"), results)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

// --- Behavioral scanner floor across modes ---

func TestBehavioralScanner_AlwaysQuarantined_PermissiveMode(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModePermissive
	engine := policy.NewEngine(cfg, nil)

	// behavioral scanner MEDIUM → effective HIGH → QUARANTINE even in permissive
	results := []scanner.ScanResult{suspiciousResult("ai-scanner", scanner.SeverityMedium)}
	result := engine.Evaluate(context.Background(), pypiArtifact("inquire", "1.1.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
}

func TestBehavioralScanner_AlwaysQuarantined_BalancedMode(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModeBalanced
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{suspiciousResult("guarddog", scanner.SeverityMedium)}
	result := engine.Evaluate(context.Background(), pypiArtifact("evil-pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionQuarantine, result.Action)
}

func TestPermissiveMode_LowSeverity_AllowWithWarning(t *testing.T) {
	cfg := defaultEngineConfig()
	cfg.Mode = policy.PolicyModePermissive
	engine := policy.NewEngine(cfg, nil)

	results := []scanner.ScanResult{suspiciousResult("osv", scanner.SeverityLow)}
	result := engine.Evaluate(context.Background(), pypiArtifact("pkg", "1.0.0"), results)
	assert.Equal(t, policy.ActionAllowWithWarning, result.Action)
}
