package trivy

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// compile-time interface check
var _ scanner.Scanner = (*TrivyScanner)(nil)

// TrivyScanner runs trivy as a subprocess and parses its JSON output.
//
// When SBOMEnabled is true (default), Trivy is invoked once per artifact in
// CycloneDX mode with both vuln and license scanners enabled. Vulnerability
// findings and component licenses are extracted from the same output — this
// avoids a second Trivy subprocess that would halve scan throughput due to
// the Trivy cache file lock.
//
// When SBOMEnabled is false, Trivy falls back to the legacy native-JSON mode
// used in v1.1 and earlier.
type TrivyScanner struct {
	binaryPath  string
	cacheDir    string
	timeout     time.Duration
	sbomEnabled bool
}

// NewTrivyScanner returns a scanner in legacy (vuln-only) mode.
func NewTrivyScanner(binaryPath, cacheDir string, timeout time.Duration) *TrivyScanner {
	return &TrivyScanner{
		binaryPath:  binaryPath,
		cacheDir:    cacheDir,
		timeout:     timeout,
		sbomEnabled: false,
	}
}

// NewTrivyScannerWithSBOM returns a scanner that emits CycloneDX SBOMs.
func NewTrivyScannerWithSBOM(binaryPath, cacheDir string, timeout time.Duration) *TrivyScanner {
	return &TrivyScanner{
		binaryPath:  binaryPath,
		cacheDir:    cacheDir,
		timeout:     timeout,
		sbomEnabled: true,
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

	if s.sbomEnabled {
		return s.scanCycloneDX(ctx, artifact, start)
	}
	return s.scanLegacy(ctx, artifact, start)
}

// scanCycloneDX runs trivy once in CycloneDX mode and parses both vuln and
// license data from the same output.
func (s *TrivyScanner) scanCycloneDX(ctx context.Context, artifact scanner.Artifact, start time.Time) (scanner.ScanResult, error) {
	// Trivy's `fs <singlefile>` mode treats the path as a binary file and does
	// not introspect package archives — wheels, npm tarballs, NuGet packages,
	// and gems all yield empty SBOMs. To get vuln + license metadata we
	// extract supported archive formats into a temp dir and scan that.
	scanPath, cleanup, err := s.prepareScanPath(artifact)
	if err != nil {
		// Failing extraction is not a security issue — fall back to scanning
		// the raw file. Trivy may still report nothing useful but the scan
		// will not fail-closed unexpectedly.
		scanPath = artifact.LocalPath
	}
	defer cleanup()

	scanArtifact := artifact
	scanArtifact.LocalPath = scanPath

	args := s.buildCycloneDXArgs(scanArtifact)
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

	result := parseCycloneDX(output)
	result.ScannerID = s.Name()
	result.Duration = time.Since(start)
	result.ScannedAt = time.Now()
	result.SBOMContent = output
	result.SBOMFormat = "cyclonedx-json"

	// Trivy 0.50 only detects packages from lockfiles, not from a single
	// installed package's metadata files. For proxy artifacts we walk the
	// extracted dir ourselves and merge the discovered licenses back in.
	// No-op when extraction wasn't applicable (Docker, raw files).
	if scanPath != artifact.LocalPath {
		if extra := extractLicensesFromDir(scanPath); len(extra) > 0 {
			seen := make(map[string]struct{}, len(result.Licenses)+len(extra))
			for _, l := range result.Licenses {
				seen[l] = struct{}{}
			}
			for _, l := range extra {
				// Normalize via the shared SBOM alias map so values like
				// "Apache License, Version 2.0" or "The GNU General Public
				// License, v2 with FOSS exception" become canonical SPDX
				// IDs that match policy lists. Unknown strings pass through
				// untouched (still useful for unknown_action / audit logs).
				canon, _ := sbom.NameAliasToID(l)
				if _, ok := seen[canon]; !ok {
					result.Licenses = append(result.Licenses, canon)
					seen[canon] = struct{}{}
				}
			}
		}
	}

	return result, nil
}

// prepareScanPath sniffs the file's magic bytes and, for known archive
// formats, extracts it into a fresh temp directory so Trivy can walk the
// unpacked tree. This is required for license + transitive-dep extraction;
// `trivy fs <wheel.whl>` against a single file produces an empty SBOM
// because Trivy's package detectors only fire on directory layouts.
//
// We sniff content rather than extension because adapters (e.g.
// internal/adapter/pypi) save the upstream artifact to a tempfile named
// `shieldoo-gate-pypi-*.tmp` — the original `.whl` / `.tgz` / `.nupkg`
// suffix is lost by the time the scanner sees the path.
//
// Magic-byte detection covers the formats we care about:
//   - ZIP   (PK\x03\x04) — wheels, JARs, nupkgs, Go module zips, zip-style npm pkgs
//   - GZIP  (\x1f\x8b)   — sdists (.tar.gz), npm tarballs (.tgz), Cargo crates
//
// Returns (path-to-scan, cleanup-fn, err). On error or unrecognized format
// the original path is returned with a no-op cleanup. Cleanup is always safe
// to call — `defer cleanup()` is the caller pattern.
func (s *TrivyScanner) prepareScanPath(artifact scanner.Artifact) (string, func(), error) {
	noop := func() {}
	if artifact.Ecosystem == scanner.EcosystemDocker {
		return artifact.LocalPath, noop, nil
	}

	kind, err := sniffArchive(artifact.LocalPath)
	if err != nil || kind == archiveUnknown {
		return artifact.LocalPath, noop, err
	}

	tmp, err := os.MkdirTemp("", "shieldoo-trivy-*")
	if err != nil {
		return artifact.LocalPath, noop, fmt.Errorf("trivy scanner: temp dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	switch kind {
	case archiveZip:
		if err := unzip(artifact.LocalPath, tmp); err != nil {
			cleanup()
			return artifact.LocalPath, noop, err
		}
		return tmp, cleanup, nil

	case archiveGzip:
		// Could be tar.gz (most package archives) or a single .gz file.
		// Try tar.gz first.
		if err := untar(artifact.LocalPath, tmp, true); err != nil {
			// Not a tar inside the gzip — fall back to plain decompress.
			cleanup()
			tmp2, err2 := os.MkdirTemp("", "shieldoo-trivy-*")
			if err2 != nil {
				return artifact.LocalPath, noop, err2
			}
			cleanup2 := func() { _ = os.RemoveAll(tmp2) }
			if err := gunzipFile(artifact.LocalPath, filepath.Join(tmp2, "content")); err != nil {
				cleanup2()
				return artifact.LocalPath, noop, err
			}
			return tmp2, cleanup2, nil
		}
		// Successfully untar'd. Some formats (e.g. .gem) are tar containing
		// nested data.tar.gz / metadata.gz — unpack those too.
		s.extractInnerArchives(tmp)
		return tmp, cleanup, nil
	}

	cleanup()
	return artifact.LocalPath, noop, nil
}

// archiveKind classifies the outer container format so prepareScanPath can
// pick the right extraction strategy.
type archiveKind int

const (
	archiveUnknown archiveKind = iota
	archiveZip
	archiveGzip
)

// sniffArchive reads the first few bytes of the file and identifies the
// container format. Returns archiveUnknown for plain text, executables,
// already-extracted tarballs, etc. — those are scanned by Trivy as-is.
func sniffArchive(path string) (archiveKind, error) {
	f, err := os.Open(path) //nolint:gosec // operator-controlled cache path
	if err != nil {
		return archiveUnknown, err
	}
	defer f.Close()

	var hdr [4]byte
	n, err := f.Read(hdr[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return archiveUnknown, err
	}
	if n < 2 {
		return archiveUnknown, nil
	}
	// ZIP local file header (PK\x03\x04) or empty-archive marker (PK\x05\x06)
	// or spanned-archive (PK\x07\x08).
	if n >= 4 && hdr[0] == 'P' && hdr[1] == 'K' &&
		(hdr[2] == 0x03 || hdr[2] == 0x05 || hdr[2] == 0x07) {
		return archiveZip, nil
	}
	// Gzip magic: 1f 8b.
	if hdr[0] == 0x1f && hdr[1] == 0x8b {
		return archiveGzip, nil
	}
	return archiveUnknown, nil
}

// gunzipFile decompresses a .gz file to dest.
func gunzipFile(src, dest string) error {
	f, err := os.Open(src) //nolint:gosec // operator-controlled cache path
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	out, err := os.Create(dest) //nolint:gosec // sandbox path
	if err != nil {
		return err
	}
	defer out.Close()
	const max = 200 * 1024 * 1024
	if _, err := io.CopyN(out, gz, max); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// extractInnerArchives walks `dir` looking for nested .tar.gz / .gz files
// (e.g. RubyGems' data.tar.gz / metadata.gz) and unpacks them in-place.
// Errors are swallowed — best-effort license discovery, not a hard guarantee.
func (s *TrivyScanner) extractInnerArchives(dir string) {
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		low := strings.ToLower(path)
		switch {
		case strings.HasSuffix(low, ".tar.gz"), strings.HasSuffix(low, ".tgz"):
			sub := path + ".x"
			_ = os.MkdirAll(sub, 0o755)
			_ = untar(path, sub, true)
		case strings.HasSuffix(low, ".gz"):
			// gunzip in-place to <path>.x
			f, err := os.Open(path) //nolint:gosec // path is inside our extraction sandbox
			if err != nil {
				return nil
			}
			defer f.Close()
			gz, err := gzip.NewReader(f)
			if err != nil {
				return nil
			}
			defer gz.Close()
			out, err := os.Create(path + ".x") //nolint:gosec // sandbox path
			if err != nil {
				return nil
			}
			defer out.Close()
			_, _ = io.Copy(out, gz) //nolint:gosec // bounded by archive size
		}
		return nil
	})
}

// unzip extracts a ZIP archive into dest. Refuses paths escaping dest
// (zip-slip protection).
func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("trivy scanner: open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if err := writeZipEntry(f, dest); err != nil {
			return err
		}
	}
	return nil
}

func writeZipEntry(f *zip.File, dest string) error {
	target := filepath.Join(dest, f.Name) //nolint:gosec // validated below
	rel, err := filepath.Rel(dest, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("trivy scanner: zip-slip detected: %q", f.Name)
	}
	if f.FileInfo().IsDir() {
		return os.MkdirAll(target, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // sandbox path
	if err != nil {
		return err
	}
	defer out.Close()

	// Cap entry size at 200MB to keep a malformed archive from filling disk.
	const maxEntrySize = 200 * 1024 * 1024
	if _, err := io.CopyN(out, rc, maxEntrySize); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// untar extracts a TAR (or TAR.GZ if gzipped=true) archive into dest.
func untar(src, dest string, gzipped bool) error {
	f, err := os.Open(src) //nolint:gosec // operator-controlled cache path
	if err != nil {
		return fmt.Errorf("trivy scanner: open tar: %w", err)
	}
	defer f.Close()

	var reader io.Reader = f
	if gzipped {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("trivy scanner: gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("trivy scanner: tar next: %w", err)
		}
		target := filepath.Join(dest, hdr.Name) //nolint:gosec // validated below
		rel, relErr := filepath.Rel(dest, target)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("trivy scanner: tar-slip detected: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // sandbox path
			if err != nil {
				return err
			}
			const maxEntrySize = 200 * 1024 * 1024
			if _, err := io.CopyN(out, tr, maxEntrySize); err != nil && !errors.Is(err, io.EOF) {
				out.Close()
				return err
			}
			out.Close()
		default:
			// Skip symlinks and special files — license metadata is in
			// regular files and we want to avoid symlink-traversal risks.
		}
	}
}

// scanLegacy is the previous native-JSON code path. Retained as a fallback
// for deployments with sbom.enabled=false (e.g. constrained environments).
func (s *TrivyScanner) scanLegacy(ctx context.Context, artifact scanner.Artifact, start time.Time) (scanner.ScanResult, error) {
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

// buildCycloneDXArgs returns the trivy CLI args for single-run CycloneDX mode.
func (s *TrivyScanner) buildCycloneDXArgs(artifact scanner.Artifact) []string {
	var args []string
	if artifact.Ecosystem == scanner.EcosystemDocker {
		args = []string{"image", "--input", artifact.LocalPath}
	} else {
		args = []string{"fs", artifact.LocalPath}
	}
	args = append(args,
		"--format", "cyclonedx",
		"--scanners", "vuln,license",
		"--quiet",
	)
	if s.cacheDir != "" {
		args = append(args, "--cache-dir", s.cacheDir)
	}
	return args
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

// --- Legacy native JSON output types ---

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

// parseOutput converts raw trivy (native JSON) bytes into a ScanResult.
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

// --- CycloneDX output types (Trivy-specific extension) ---

// trivyCycloneDX matches Trivy's CycloneDX-with-vulnerabilities output.
// CycloneDX 1.5 places vulnerabilities at the top level in an optional
// "vulnerabilities" array. Licenses are read from components[].licenses.
type trivyCycloneDX struct {
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []cdxVuln      `json:"vulnerabilities"`
}

type cdxComponent struct {
	Name     string           `json:"name"`
	Version  string           `json:"version"`
	PURL     string           `json:"purl"`
	Licenses []cdxLicenseWrap `json:"licenses"`
}

type cdxLicenseWrap struct {
	License    *cdxLicense `json:"license,omitempty"`
	Expression string      `json:"expression,omitempty"`
}

type cdxLicense struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cdxVuln struct {
	ID        string       `json:"id"`
	BOMRef    string       `json:"bom-ref"`
	Ratings   []cdxRating  `json:"ratings"`
	Advisors  []any        `json:"advisories"`
	Affects   []cdxAffect  `json:"affects"`
	Source    cdxVulnSrc   `json:"source"`
	Analysis  cdxAnalysis  `json:"analysis"`
	CwesArr   []int        `json:"cwes"`
	CreatedAt string       `json:"created"`
	Updated   string       `json:"updated"`
	Descrip   string       `json:"description"`
}

type cdxRating struct {
	Source   cdxVulnSrc `json:"source"`
	Score    float64    `json:"score"`
	Severity string     `json:"severity"`
	Method   string     `json:"method"`
	Vector   string     `json:"vector"`
}

type cdxVulnSrc struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

type cdxAnalysis struct {
	State string `json:"state"`
}

// parseCycloneDX extracts vulnerabilities and licenses from a Trivy CycloneDX
// JSON output. On parse error the scanner fails open (VerdictClean).
func parseCycloneDX(data []byte) scanner.ScanResult {
	var bom trivyCycloneDX
	if err := json.Unmarshal(data, &bom); err != nil {
		return scanner.ScanResult{
			Verdict: scanner.VerdictClean,
			Error:   fmt.Errorf("trivy scanner: parsing cyclonedx output: %w", err),
		}
	}

	// Build bom-ref → component lookup for vuln location.
	refToName := make(map[string]string, len(bom.Components))
	for _, c := range bom.Components {
		if c.PURL != "" {
			refToName[c.PURL] = c.Name
		}
	}

	// Vulnerabilities → Findings.
	var findings []scanner.Finding
	for _, v := range bom.Vulnerabilities {
		sev := highestSeverity(v.Ratings)
		loc := v.BOMRef
		for _, af := range v.Affects {
			if n, ok := refToName[af.Ref]; ok {
				loc = n
				break
			}
		}
		findings = append(findings, scanner.Finding{
			Severity:    sev,
			Category:    v.ID,
			Description: firstNonEmpty(v.Descrip, v.ID),
			Location:    loc,
		})
	}

	// Licenses.
	licSet := make(map[string]struct{})
	for _, c := range bom.Components {
		for _, lw := range c.Licenses {
			if lw.Expression != "" {
				licSet[strings.TrimSpace(lw.Expression)] = struct{}{}
				continue
			}
			if lw.License == nil {
				continue
			}
			switch {
			case lw.License.ID != "":
				licSet[lw.License.ID] = struct{}{}
			case lw.License.Name != "":
				licSet[lw.License.Name] = struct{}{}
			}
		}
	}
	licenses := make([]string, 0, len(licSet))
	for id := range licSet {
		if id != "" {
			licenses = append(licenses, id)
		}
	}

	res := scanner.ScanResult{
		Licenses: licenses,
	}
	if len(findings) == 0 {
		res.Verdict = scanner.VerdictClean
		res.Confidence = 1.0
	} else {
		res.Verdict = scanner.VerdictSuspicious
		res.Confidence = 0.9
		res.Findings = findings
	}
	return res
}

// highestSeverity picks the worst severity out of a rating list.
func highestSeverity(ratings []cdxRating) scanner.Severity {
	best := scanner.SeverityInfo
	rank := map[scanner.Severity]int{
		scanner.SeverityInfo: 0, scanner.SeverityLow: 1, scanner.SeverityMedium: 2,
		scanner.SeverityHigh: 3, scanner.SeverityCritical: 4,
	}
	for _, r := range ratings {
		sev := mapSeverity(r.Severity)
		if rank[sev] > rank[best] {
			best = sev
		}
	}
	return best
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

func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		if p != "" {
			return p
		}
	}
	return ""
}

