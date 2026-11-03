package builtin

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
func (p *PTHInspector) Version() string { return "1.1.0" }

func (p *PTHInspector) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI}
}

func (p *PTHInspector) HealthCheck(_ context.Context) error { return nil }

// Scan opens the wheel archive and checks all .pth files for executable code.
func (p *PTHInspector) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	// pth-inspector only applies to Python wheels (.whl). A wheel is a zip whose
	// site-packages .pth files are auto-executed at interpreter start-up; sdists
	// (.tar.gz) and other PyPI artifacts are not wheels — and not even zip
	// archives, so zip.OpenReader fails on them. Skip non-wheel artifacts cleanly
	// so that marking pth-inspector `required` does not fail closed on every
	// normal sdist.
	if !strings.HasSuffix(strings.ToLower(wheelFilename(artifact)), ".whl") {
		return buildResult(p.Name(), start, scanner.VerdictClean, 1.0, nil), nil
	}

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
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		if isCanonicalSetuptoolsPTH(artifact.Name, f.Name, content) {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(content))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			if isPTHExecutable(line) {
				findings = append(findings, scanner2Finding(f.Name, lineNum, line))
			}
		}
	}

	if len(findings) > 0 {
		return buildResult(p.Name(), start, scanner.VerdictMalicious, 0.95, findings), nil
	}
	return buildResult(p.Name(), start, scanner.VerdictClean, 1.0, nil), nil
}

// wheelFilename recovers the artifact's original filename for the wheel-suffix
// check. Filename is the explicit, preferred source (set by the PyPI adapter on
// fresh scans). When it is unset — e.g. the rescan scheduler builds
// scanner.Artifact without it — the PyPI artifact ID still encodes the original
// filename as its 4th colon segment (ecosystem:name:version:filename), which is
// reliable where LocalPath is not: cache backends hand back extensionless temp
// paths (shieldoo-s3-cache-*, *.tmp), and an extensionless path would otherwise
// look like a non-wheel and let a malicious cached wheel be skipped as clean on
// rescan. LocalPath is only a last resort.
func wheelFilename(a scanner.Artifact) string {
	if a.Filename != "" {
		return a.Filename
	}
	if parts := strings.SplitN(a.ID, ":", 4); len(parts) == 4 && parts[3] != "" {
		return parts[3]
	}
	return a.LocalPath
}

// setuptoolsPTHHashes are the SHA-256 digests of the distutils-precedence.pth
// shim that setuptools ships in every wheel: the 'local' default (>= 60) and
// the older 'stdlib' default (49-59).
var setuptoolsPTHHashes = map[string]bool{
	"2638ce9e2500e572a5e0de7faed6661eb569d1b696fcba07b0dd223da5f5d224": true,
	"7ea7ffef3fe2a117ee12c68ed6553617f0d7fd2f0590257c25c484959a3b7373": true,
}

// isCanonicalSetuptoolsPTH reports whether a .pth file is the byte-identical
// setuptools shim at the wheel root. The package name is part of the check,
// because the shim imports _distutils_hack from the same wheel: in any other
// package the same bytes would load attacker code.
func isCanonicalSetuptoolsPTH(pkgName, path string, content []byte) bool {
	if !strings.EqualFold(pkgName, "setuptools") || path != "distutils-precedence.pth" {
		return false
	}
	sum := sha256.Sum256(content)
	return setuptoolsPTHHashes[hex.EncodeToString(sum[:])]
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
