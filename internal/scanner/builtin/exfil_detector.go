package builtin

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*ExfilDetector)(nil)

// urlPattern matches http:// and https:// URLs in source code.
var urlPattern = regexp.MustCompile(`https?://[^\s"'\)\]>]+`)

// safeDomains is the allowlist of registry / trusted domains that are
// considered benign when referenced from package code.
var safeDomains = []string{
	"pypi.org",
	"files.pythonhosted.org",
	"npmjs.org",
	"npmjs.com",
	"registry.npmjs.org",
	"github.com",
	"githubusercontent.com",
	"raw.githubusercontent.com",
	"nuget.org",
	"api.nuget.org",
	"docker.io",
	"registry-1.docker.io",
	"gcr.io",
	"ghcr.io",
	"quay.io",
	"pkg.go.dev",
	"golang.org",
	"mozilla.org",
	"w3.org",
	"example.com",
	"localhost",
}

// ExfilDetector scans code files for HTTP calls to domains that are not in
// the known-safe registry allowlist, which may indicate data exfiltration.
type ExfilDetector struct{}

// NewExfilDetector creates a new ExfilDetector.
func NewExfilDetector() *ExfilDetector {
	return &ExfilDetector{}
}

func (e *ExfilDetector) Name() string    { return "exfil-detector" }
func (e *ExfilDetector) Version() string { return "1.0.0" }

func (e *ExfilDetector) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemDocker,
		scanner.EcosystemNuGet,
	}
}

func (e *ExfilDetector) HealthCheck(_ context.Context) error { return nil }

// Scan walks the artifact path and looks for URLs pointing to non-registry hosts.
func (e *ExfilDetector) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	findings, err := e.walk(artifact.LocalPath)
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: e.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("exfil-detector: %w", err),
		}, nil
	}

	if len(findings) > 0 {
		return buildResult(e.Name(), start, scanner.VerdictSuspicious, 0.75, findings), nil
	}
	return buildResult(e.Name(), start, scanner.VerdictClean, 1.0, nil), nil
}

func (e *ExfilDetector) walk(root string) ([]scanner.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	var findings []scanner.Finding

	if !info.IsDir() {
		if codeExtensions[fileExt(root)] {
			ff, err := e.scanFile(root)
			if err != nil {
				return nil, err
			}
			findings = append(findings, ff...)
		}
		return findings, nil
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !codeExtensions[fileExt(path)] {
			return nil
		}
		ff, err := e.scanFile(path)
		if err != nil {
			return nil
		}
		findings = append(findings, ff...)
		return nil
	})
	return findings, err
}

func (e *ExfilDetector) scanFile(path string) ([]scanner.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []scanner.Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		urls := urlPattern.FindAllString(line, -1)
		for _, u := range urls {
			if !isSafeDomain(u) {
				findings = append(findings, scanner.Finding{
					Severity:    scanner.SeverityMedium,
					Category:    "network-exfiltration",
					Description: "HTTP call to non-registry domain detected",
					Location:    fmt.Sprintf("%s:%d", path, lineNum),
					IoCs:        []string{u},
				})
			}
		}
	}
	return findings, nil
}

// isSafeDomain returns true when the URL's host matches a known-safe domain
// or one of its subdomains.
func isSafeDomain(rawURL string) bool {
	// Extract host from URL without importing net/url to keep it lightweight.
	// Format: scheme://host/path?query
	rest := rawURL
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	// Strip path/query/fragment
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(rest, sep); idx >= 0 {
			rest = rest[:idx]
		}
	}
	// Strip port
	if idx := strings.LastIndex(rest, ":"); idx >= 0 {
		rest = rest[:idx]
	}
	host := strings.ToLower(rest)

	for _, safe := range safeDomains {
		if host == safe || strings.HasSuffix(host, "."+safe) {
			return true
		}
	}
	return false
}
