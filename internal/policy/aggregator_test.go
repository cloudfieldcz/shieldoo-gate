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

func TestAggregate_TaggedFindings_PopulatedCorrectly(t *testing.T) {
	results := []scanner.ScanResult{
		{
			ScannerID:  "osv",
			Verdict:    scanner.VerdictSuspicious,
			Confidence: 0.9,
			Findings: []scanner.Finding{
				{Severity: scanner.SeverityMedium, Category: "ReDoS", Description: "CVE-2022-123"},
			},
		},
		{
			ScannerID:  "trivy",
			Verdict:    scanner.VerdictClean,
			Confidence: 0.95,
			Findings: []scanner.Finding{
				{Severity: scanner.SeverityInfo, Category: "info", Description: "no issues"},
			},
		},
	}
	got := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictSuspicious, got.Verdict)
	assert.Len(t, got.Tagged, 2)
	assert.Equal(t, "osv", got.Tagged[0].ScannerID)
	assert.Equal(t, scanner.VerdictSuspicious, got.Tagged[0].ScannerVerdict)
}

func TestMaxEffectiveSeverity_MultipleFindings(t *testing.T) {
	results := []scanner.ScanResult{
		{
			ScannerID:  "osv",
			Verdict:    scanner.VerdictSuspicious,
			Confidence: 0.9,
			Findings: []scanner.Finding{
				{Severity: scanner.SeverityMedium, Category: "ReDoS"},
				{Severity: scanner.SeverityCritical, Category: "RCE"},
			},
		},
	}
	agg := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.SeverityCritical, agg.MaxEffectiveSeverity())
}

func TestMaxEffectiveSeverity_EmptyFindings_ReturnsHigh(t *testing.T) {
	// SUSPICIOUS without findings is an anomaly → HIGH
	results := []scanner.ScanResult{
		{
			ScannerID:  "osv",
			Verdict:    scanner.VerdictSuspicious,
			Confidence: 0.9,
			Findings:   nil, // no findings
		},
	}
	agg := policy.Aggregate(results, defaultCfg())
	assert.Equal(t, scanner.VerdictSuspicious, agg.Verdict)
	assert.Equal(t, scanner.SeverityHigh, agg.MaxEffectiveSeverity())
}

func TestMaxEffectiveSeverity_OnlySuspiciousFindings(t *testing.T) {
	results := []scanner.ScanResult{
		{
			ScannerID:  "osv",
			Verdict:    scanner.VerdictSuspicious,
			Confidence: 0.9,
			Findings: []scanner.Finding{
				{Severity: scanner.SeverityMedium, Category: "ReDoS"},
			},
		},
		{
			ScannerID:  "trivy",
			Verdict:    scanner.VerdictClean,
			Confidence: 0.95,
			Findings: []scanner.Finding{
				{Severity: scanner.SeverityCritical, Category: "info"},
			},
		},
	}
	agg := policy.Aggregate(results, defaultCfg())
	// Only SUSPICIOUS scanner findings count — trivy is CLEAN
	suspicious := agg.SuspiciousFindings()
	assert.Len(t, suspicious, 1)
	assert.Equal(t, scanner.SeverityMedium, agg.MaxEffectiveSeverity())
}

func TestMaxEffectiveSeverity_BehavioralFloor_Applied(t *testing.T) {
	results := []scanner.ScanResult{
		{
			ScannerID:  "ai-scanner",
			Verdict:    scanner.VerdictSuspicious,
			Confidence: 0.9,
			Findings: []scanner.Finding{
				{Severity: scanner.SeverityMedium, Category: "obfuscation"},
			},
		},
	}
	agg := policy.Aggregate(results, defaultCfg())
	// behavioral scanner MEDIUM → effective HIGH (floor)
	assert.Equal(t, scanner.SeverityHigh, agg.MaxEffectiveSeverity())
}
