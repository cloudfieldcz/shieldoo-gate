package trivy

import (
	"context"
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestTrivyScanner_ParseOutput_CleanResult(t *testing.T) {
	output := `{"Results":[]}`
	result := parseOutput([]byte(output))
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestTrivyScanner_ParseOutput_WithVulnerabilities(t *testing.T) {
	output := `{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1234","Severity": "HIGH","Title": "Test vulnerability","PkgName": "test-pkg"}]}]}`
	result := parseOutput([]byte(output))
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.Len(t, result.Findings, 1)
	assert.Equal(t, "CVE-2024-1234", result.Findings[0].Category)
}

func TestTrivyScanner_ParseOutput_CriticalVuln(t *testing.T) {
	output := `{"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-9999","Severity": "CRITICAL","Title": "Critical RCE","PkgName": "evil"}]}]}`
	result := parseOutput([]byte(output))
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.Equal(t, scanner.SeverityCritical, result.Findings[0].Severity)
}

func TestTrivyScanner_SupportedEcosystems(t *testing.T) {
	s := &TrivyScanner{}
	eco := s.SupportedEcosystems()
	assert.Contains(t, eco, scanner.EcosystemDocker)
	assert.Contains(t, eco, scanner.EcosystemPyPI)
	assert.Contains(t, eco, scanner.EcosystemNPM)
	assert.Contains(t, eco, scanner.EcosystemNuGet)
}

func TestTrivyScanner_HealthCheck_BinaryNotFound(t *testing.T) {
	s := NewTrivyScanner("/nonexistent/trivy", t.TempDir(), 30*time.Second)
	err := s.HealthCheck(context.Background())
	assert.Error(t, err)
}

var _ scanner.Scanner = (*TrivyScanner)(nil)

func TestAppendTMPDIR_AddsNew(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin"}
	result := appendTMPDIR(env, "/my/tmp")
	assert.Contains(t, result, "HOME=/home/user")
	assert.Contains(t, result, "PATH=/usr/bin")
	assert.Contains(t, result, "TMPDIR=/my/tmp")
}

func TestAppendTMPDIR_ReplacesExisting(t *testing.T) {
	env := []string{"HOME=/home/user", "TMPDIR=/old/tmp", "PATH=/usr/bin"}
	result := appendTMPDIR(env, "/new/tmp")
	assert.Contains(t, result, "TMPDIR=/new/tmp")
	assert.NotContains(t, result, "TMPDIR=/old/tmp")
	assert.Equal(t, len(env), len(result)) // same count (replaced, not added)
}
