package policy_test

import (
	"fmt"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func defaultCfg() policy.AggregationConfig {
	return policy.AggregationConfig{MinConfidence: 0.5}
}

func TestAggregate_ThreatFeedHit_ImmediateMalicious(t *testing.T) {
	results := []scanner.ScanResult{
		{ScannerID: "builtin-threat-feed", Verdict: scanner.VerdictMalicious, Confidence: 1.0},
		{ScannerID: "trivy", Verdict: scanner.VerdictClean, Confidence: 0.9},
	}
	got := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictMalicious, got.Verdict)
}

func TestAggregate_MaliciousHighConfidence_ReturnsMalicious(t *testing.T) {
	results := []scanner.ScanResult{
		{ScannerID: "guarddog", Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}
	got := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictMalicious, got.Verdict)
}

func TestAggregate_MaliciousLowConfidence_DowngradedToClean(t *testing.T) {
	results := []scanner.ScanResult{
		{ScannerID: "guarddog", Verdict: scanner.VerdictMalicious, Confidence: 0.2},
	}
	got := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictClean, got.Verdict)
}

func TestAggregate_SuspiciousHighConfidence_ReturnsSuspicious(t *testing.T) {
	results := []scanner.ScanResult{
		{ScannerID: "osv", Verdict: scanner.VerdictSuspicious, Confidence: 0.8},
	}
	got := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictSuspicious, got.Verdict)
}

func TestAggregate_AllClean_ReturnsClean(t *testing.T) {
	results := []scanner.ScanResult{
		{ScannerID: "trivy", Verdict: scanner.VerdictClean, Confidence: 0.95},
		{ScannerID: "osv", Verdict: scanner.VerdictClean, Confidence: 0.90},
	}
	got := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictClean, got.Verdict)
}

func TestAggregate_AllErrors_ReturnsClean(t *testing.T) {
	results := []scanner.ScanResult{
		{ScannerID: "trivy", Error: fmt.Errorf("timeout"), Confidence: 0.9},
		{ScannerID: "guarddog", Error: fmt.Errorf("timeout"), Confidence: 0.9},
	}
	got := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictClean, got.Verdict)
}

func TestAggregate_EmptyResults_ReturnsClean(t *testing.T) {
	got := policy.Aggregate(nil, defaultCfg())
	assert.Equal(t, scanner.VerdictClean, got.Verdict)
}
