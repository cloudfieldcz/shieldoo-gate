package builtin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*InstallHookAnalyzer)(nil)

// suspiciousInstallPatterns are code patterns that indicate potentially malicious
// behaviour in setup.py hooks or npm install scripts.
var suspiciousInstallPatterns = []string{
	"subprocess",
	"os.system",
	"popen",
	"exec(",
	"eval(",
	"compile(",
	"__import__",
	"curl ",
	"wget ",
	"powershell",
	"socket.connect",
	"urllib.request",
}

// npmHookScripts are the npm lifecycle scripts that run code during install/uninstall.
var npmHookScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"preuninstall",
	"postuninstall",
}

// InstallHookAnalyzer scans PyPI setup.py and npm package.json for suspicious
// install-time hooks that could execute arbitrary code.
type InstallHookAnalyzer struct{}

// NewInstallHookAnalyzer creates a new InstallHookAnalyzer.
func NewInstallHookAnalyzer() *InstallHookAnalyzer {
	return &InstallHookAnalyzer{}
}

func (a *InstallHookAnalyzer) Name() string    { return "install-hook-analyzer" }
func (a *InstallHookAnalyzer) Version() string { return "1.0.0" }

func (a *InstallHookAnalyzer) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM}
}

func (a *InstallHookAnalyzer) HealthCheck(_ context.Context) error { return nil }

// Scan inspects setup.py (PyPI) or package.json scripts (NPM) for suspicious patterns.
func (a *InstallHookAnalyzer) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	var findings []scanner.Finding
	var scanErr error

	switch artifact.Ecosystem {
	case scanner.EcosystemPyPI:
		findings, scanErr = a.scanSetupPy(artifact.LocalPath)
	case scanner.EcosystemNPM:
		findings, scanErr = a.scanPackageJSON(artifact.LocalPath)
	}

	if scanErr != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: a.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     scanErr,
		}, nil
	}

	if len(findings) > 0 {
		return buildResult(a.Name(), start, scanner.VerdictSuspicious, 0.80, findings), nil
	}
	return buildResult(a.Name(), start, scanner.VerdictClean, 1.0, nil), nil
}

// scanSetupPy reads setup.py line by line and flags suspicious patterns.
func (a *InstallHookAnalyzer) scanSetupPy(localPath string) ([]scanner.Finding, error) {
	setupPy := filepath.Join(localPath, "setup.py")
	f, err := os.Open(setupPy)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("install-hook-analyzer: open setup.py: %w", err)
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		lower := strings.ToLower(line)
		for _, pat := range suspiciousInstallPatterns {
			if strings.Contains(lower, pat) {
				findings = append(findings, scanner.Finding{
					Severity:    scanner.SeverityHigh,
					Category:    "suspicious-install-hook",
					Description: fmt.Sprintf("Suspicious pattern %q in setup.py", pat),
					Location:    fmt.Sprintf("setup.py:%d", lineNum),
					IoCs:        []string{strings.TrimSpace(line)},
				})
				break // one finding per line is enough
			}
		}
	}
	return findings, nil
}

// scanPackageJSON reads package.json and checks lifecycle script values for
// suspicious patterns.
func (a *InstallHookAnalyzer) scanPackageJSON(localPath string) ([]scanner.Finding, error) {
	pkgJSON := filepath.Join(localPath, "package.json")
	data, err := os.ReadFile(pkgJSON)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("install-hook-analyzer: read package.json: %w", err)
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("install-hook-analyzer: parse package.json: %w", err)
	}

	var findings []scanner.Finding
	for _, scriptName := range npmHookScripts {
		scriptVal, ok := pkg.Scripts[scriptName]
		if !ok {
			continue
		}
		lower := strings.ToLower(scriptVal)
		for _, pat := range suspiciousInstallPatterns {
			if strings.Contains(lower, pat) {
				findings = append(findings, scanner.Finding{
					Severity:    scanner.SeverityHigh,
					Category:    "suspicious-npm-hook",
					Description: fmt.Sprintf("Suspicious pattern %q in npm %s script", pat, scriptName),
					Location:    fmt.Sprintf("package.json scripts.%s", scriptName),
					IoCs:        []string{scriptVal},
				})
				break
			}
		}
	}
	return findings, nil
}
