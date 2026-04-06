package policy_test

import (
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestScannerCategory_BehavioralScanners(t *testing.T) {
	behavioral := []string{
		"guarddog", "ai-scanner", "exfil-detector",
		"install-hook-analyzer", "pth-inspector", "obfuscation-detector",
	}
	for _, id := range behavioral {
		assert.Equal(t, policy.CategoryBehavioral, policy.ScannerCategoryFor(id), "scanner=%s", id)
	}
}

func TestScannerCategory_VulnerabilityScanners(t *testing.T) {
	vulnerability := []string{"osv", "trivy"}
	for _, id := range vulnerability {
		assert.Equal(t, policy.CategoryVulnerability, policy.ScannerCategoryFor(id), "scanner=%s", id)
	}
}

func TestEffectiveSeverity_BehavioralScanner_MediumBecomesHigh(t *testing.T) {
	eff := policy.EffectiveSeverity(scanner.SeverityMedium, "ai-scanner")
	assert.Equal(t, scanner.SeverityHigh, eff)
}

func TestEffectiveSeverity_VulnerabilityScanner_MediumStaysMedium(t *testing.T) {
	eff := policy.EffectiveSeverity(scanner.SeverityMedium, "osv")
	assert.Equal(t, scanner.SeverityMedium, eff)
}

func TestEffectiveSeverity_BehavioralScanner_HighStaysHigh(t *testing.T) {
	eff := policy.EffectiveSeverity(scanner.SeverityHigh, "guarddog")
	assert.Equal(t, scanner.SeverityHigh, eff)
}

func TestEffectiveSeverity_BehavioralScanner_CriticalStaysCritical(t *testing.T) {
	eff := policy.EffectiveSeverity(scanner.SeverityCritical, "guarddog")
	assert.Equal(t, scanner.SeverityCritical, eff)
}

func TestSeverityAtLeastHigh(t *testing.T) {
	assert.True(t, policy.SeverityAtLeastHigh(scanner.SeverityHigh))
	assert.True(t, policy.SeverityAtLeastHigh(scanner.SeverityCritical))
	assert.False(t, policy.SeverityAtLeastHigh(scanner.SeverityMedium))
	assert.False(t, policy.SeverityAtLeastHigh(scanner.SeverityLow))
	assert.False(t, policy.SeverityAtLeastHigh(scanner.SeverityInfo))
}
