package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// compile-time interface check
var _ scanner.Scanner = (*TrivyScanner)(nil)

// TrivyScanner runs trivy as a subprocess and parses its JSON output.
type TrivyScanner struct {
	binaryPath string
	cacheDir   string
	timeout    time.Duration
}

// NewTrivyScanner returns a TrivyScanner configured with the given binary path, cache directory, and scan timeout.
func NewTrivyScanner(binaryPath, cacheDir string, timeout time.Duration) *TrivyScanner {
	return &TrivyScanner{
		binaryPath: binaryPath,
		cacheDir:   cacheDir,
		timeout:    timeout,
	}
}

func (s *TrivyScanner) Name() string    { return "trivy" }
func (s *TrivyScanner) Version() string { return "0.50.0" }

// SupportedEcosystems returns all ecosystems Trivy can scan.
func (s *TrivyScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemDocker,
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemNuGet,
	}
}

// Scan runs trivy against the artifact at artifact.LocalPath and returns a ScanResult.
// On subprocess errors the scanner fails open (VerdictClean) with the error recorded in ScanResult.Error.
func (s *TrivyScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var args []string
	if artifact.Ecosystem == scanner.EcosystemDocker {
		args = []string{"image", "--input", artifact.LocalPath, "--format", "json", "--quiet"}
	} else {
		args = []string{"fs", artifact.LocalPath, "--format", "json", "--quiet"}
	}
	if s.cacheDir != "" {
		args = append(args, "--cache-dir", s.cacheDir)
	}

	//nolint:gosec // binaryPath is operator-controlled config, not user input
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			Duration:  time.Since(start),
			ScannedAt: time.Now(),
			Error:     fmt.Errorf("trivy scanner: running trivy for %s: %w", artifact.ID, err),
		}, nil
	}

	result := parseOutput(output)
	result.ScannerID = s.Name()
	result.Duration = time.Since(start)
	result.ScannedAt = time.Now()
	return result, nil
}

// HealthCheck verifies the trivy binary is present and executable by running `trivy version`.
func (s *TrivyScanner) HealthCheck(ctx context.Context) error {
	//nolint:gosec // binaryPath is operator-controlled config
	cmd := exec.CommandContext(ctx, s.binaryPath, "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy scanner: health check failed (binary=%s): %w", s.binaryPath, err)
	}
	return nil
}

// --- JSON output types ---

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	Severity        string `json:"Severity"`
	Title           string `json:"Title"`
	PkgName         string `json:"PkgName"`
}

// parseOutput converts raw trivy JSON bytes into a ScanResult.
// On parse error it fails open (VerdictClean).
func parseOutput(data []byte) scanner.ScanResult {
	var out trivyOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return scanner.ScanResult{
			Verdict: scanner.VerdictClean,
			Error:   fmt.Errorf("trivy scanner: parsing output: %w", err),
		}
	}

	var findings []scanner.Finding
	for _, result := range out.Results {
		for _, vuln := range result.Vulnerabilities {
			findings = append(findings, scanner.Finding{
				Severity:    mapSeverity(vuln.Severity),
				Category:    vuln.VulnerabilityID,
				Description: vuln.Title,
				Location:    vuln.PkgName,
			})
		}
	}

	if len(findings) == 0 {
		return scanner.ScanResult{
			Verdict:    scanner.VerdictClean,
			Confidence: 1.0,
			Findings:   nil,
		}
	}

	return scanner.ScanResult{
		Verdict:    scanner.VerdictSuspicious,
		Confidence: 0.9,
		Findings:   findings,
	}
}

// mapSeverity converts a trivy severity string to the internal Severity type.
func mapSeverity(s string) scanner.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return scanner.SeverityCritical
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	default:
		return scanner.SeverityInfo
	}
}
