package builtin

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*PTHInspector)(nil)

// PTHInspector scans PyPI wheel archives (.whl) for .pth files containing
// executable code, which is a known supply-chain attack vector.
type PTHInspector struct{}

// NewPTHInspector creates a new PTHInspector.
func NewPTHInspector() *PTHInspector {
	return &PTHInspector{}
}

func (p *PTHInspector) Name() string    { return "pth-inspector" }
func (p *PTHInspector) Version() string { return "1.0.0" }

func (p *PTHInspector) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI}
}

func (p *PTHInspector) HealthCheck(_ context.Context) error { return nil }

// Scan opens the wheel archive and checks all .pth files for executable code.
func (p *PTHInspector) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	r, err := zip.OpenReader(artifact.LocalPath)
	if err != nil {
		return scanner.ScanResult{
			Verdict:    scanner.VerdictClean,
			Confidence: 0,
			ScannerID:  p.Name(),
			Duration:   time.Since(start),
			ScannedAt:  start,
			Error:      fmt.Errorf("pth-inspector: open zip %s: %w", artifact.LocalPath, err),
		}, nil
	}
	defer r.Close()

	var findings []scanner.Finding

	for _, f := range r.File {
		if filepath.Ext(f.Name) != ".pth" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(rc)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			if isPTHExecutable(line) {
				findings = append(findings, scanner2Finding(f.Name, lineNum, line))
			}
		}
		rc.Close()
	}

	if len(findings) > 0 {
		return buildResult(p.Name(), start, scanner.VerdictMalicious, 0.95, findings), nil
	}
	return buildResult(p.Name(), start, scanner.VerdictClean, 1.0, nil), nil
}

// isPTHExecutable returns true when a .pth line contains code that would be
// executed by the Python site module at interpreter start-up.
func isPTHExecutable(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	suspects := []string{
		"import ",
		"exec(",
		"eval(",
		"__import__",
		"os.system",
		"subprocess",
	}
	lower := strings.ToLower(trimmed)
	for _, pat := range suspects {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	// Semicolon followed by import anywhere on the line is also a red flag
	if strings.Contains(trimmed, ";") {
		parts := strings.Split(trimmed, ";")
		for _, part := range parts {
			p2 := strings.TrimSpace(part)
			if strings.HasPrefix(p2, "import ") || strings.HasPrefix(p2, "from ") {
				return true
			}
		}
	}
	return false
}

func scanner2Finding(filename string, line int, content string) scanner.Finding {
	return scanner.Finding{
		Severity:    scanner.SeverityHigh,
		Category:    "pth-executable-code",
		Description: "Executable code detected in .pth file",
		Location:    fmt.Sprintf("%s:%d", filename, line),
		IoCs:        []string{content},
	}
}

// buildResult is a small helper shared by all built-in scanners.
func buildResult(scannerID string, start time.Time, verdict scanner.Verdict, confidence float32, findings []scanner.Finding) scanner.ScanResult {
	return scanner.ScanResult{
		Verdict:    verdict,
		Confidence: confidence,
		Findings:   findings,
		ScannerID:  scannerID,
		Duration:   time.Since(start),
		ScannedAt:  start,
	}
}
