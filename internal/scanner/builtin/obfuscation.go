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
var _ scanner.Scanner = (*ObfuscationDetector)(nil)

// obfuscationPatterns are regexes that detect common code obfuscation techniques
// used in supply-chain attacks.
var obfuscationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`exec\s*\(\s*base64`),
	regexp.MustCompile(`exec\s*\(\s*.*b64decode`),
	regexp.MustCompile(`eval\s*\(\s*atob\s*\(`),
	regexp.MustCompile(`eval\s*\(\s*Buffer\.from\s*\(`),
	regexp.MustCompile(`eval\s*\(\s*.*fromCharCode`),
	regexp.MustCompile(`compile\s*\(\s*base64`),
	regexp.MustCompile(`__import__\s*\(\s*['"]base64['"]\s*\).*exec`),
}

// codeExtensions are the file extensions that the scanner will inspect.
var codeExtensions = map[string]bool{
	".py":  true,
	".js":  true,
	".mjs": true,
	".cjs": true,
	".ts":  true,
	".sh":  true,
	".ps1": true,
	".bat": true,
	".rb":  true,
	".pl":  true,
	".cs":  true,
}

const maxFileSizeObfuscation = 10 * 1024 * 1024 // 10 MB

// ObfuscationDetector scans source and script files for common obfuscation
// patterns such as exec(base64...), eval(atob(...)), etc.
type ObfuscationDetector struct{}

// NewObfuscationDetector creates a new ObfuscationDetector.
func NewObfuscationDetector() *ObfuscationDetector {
	return &ObfuscationDetector{}
}

func (o *ObfuscationDetector) Name() string    { return "obfuscation-detector" }
func (o *ObfuscationDetector) Version() string { return "1.0.0" }

func (o *ObfuscationDetector) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemDocker,
		scanner.EcosystemNuGet,
	}
}

func (o *ObfuscationDetector) HealthCheck(_ context.Context) error { return nil }

// Scan walks the artifact path (file or directory) and checks each code file
// for obfuscation patterns.
func (o *ObfuscationDetector) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	findings, err := o.walk(artifact.LocalPath)
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: o.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("obfuscation-detector: %w", err),
		}, nil
	}

	if len(findings) > 0 {
		return buildResult(o.Name(), start, scanner.VerdictMalicious, 0.9, findings), nil
	}
	return buildResult(o.Name(), start, scanner.VerdictClean, 1.0, nil), nil
}

// walk handles both single-file and directory artifact paths.
func (o *ObfuscationDetector) walk(root string) ([]scanner.Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	var findings []scanner.Finding

	if !info.IsDir() {
		// Single file artifact (e.g. written by test helper writeCodeFile).
		if codeExtensions[fileExt(root)] {
			ff, err := o.scanFile(root)
			if err != nil {
				return nil, err
			}
			findings = append(findings, ff...)
		}
		return findings, nil
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}
		if !codeExtensions[fileExt(path)] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSizeObfuscation {
			return nil
		}
		ff, err := o.scanFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		findings = append(findings, ff...)
		return nil
	})
	return findings, err
}

// scanFile scans a single file for obfuscation patterns.
func (o *ObfuscationDetector) scanFile(path string) ([]scanner.Finding, error) {
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
		for _, re := range obfuscationPatterns {
			if re.MatchString(line) {
				findings = append(findings, scanner.Finding{
					Severity:    scanner.SeverityHigh,
					Category:    "obfuscated-code",
					Description: fmt.Sprintf("Obfuscation pattern %q detected", re.String()),
					Location:    fmt.Sprintf("%s:%d", path, lineNum),
					IoCs:        []string{strings.TrimSpace(line)},
				})
				break // one finding per line
			}
		}
	}
	return findings, nil
}

// fileExt returns the lower-cased file extension including the dot.
func fileExt(path string) string {
	return strings.ToLower(filepath.Ext(path))
}
