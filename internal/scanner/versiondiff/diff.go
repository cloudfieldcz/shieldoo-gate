package versiondiff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// DiffResult aggregates findings from all diff analysis strategies.
type DiffResult struct {
	FilesAdded       int
	FilesRemoved     int
	FilesModified    int
	SizeRatio        float64 // new_total / old_total
	MaxEntropyDelta  float64
	NewDependencies  []string
	SensitiveChanges []string
	Findings         []scanner.Finding
}

// RunDiff executes all five diff strategies between oldDir and newDir.
func RunDiff(oldDir, newDir string, ecosystem scanner.Ecosystem, thresholds config.VersionDiffThresholds, extraSensitive []string, entropySampleBytes int) DiffResult {
	var dr DiffResult

	// Walk both directories to get file inventories
	oldFiles := walkDir(oldDir)
	newFiles := walkDir(newDir)

	// A. File inventory diff
	added, removed, modified := fileInventoryDiff(oldDir, newDir, oldFiles, newFiles)
	dr.FilesAdded = len(added)
	dr.FilesRemoved = len(removed)
	dr.FilesModified = len(modified)

	if len(added) > thresholds.MaxNewFiles {
		dr.Findings = append(dr.Findings, scanner.Finding{
			Severity:    scanner.SeverityMedium,
			Category:    "version-diff:file-inventory",
			Description: "Unusually many new files added in this version",
			Location:    strings.Join(added[:min(5, len(added))], ", "),
		})
	}

	// B. Size anomaly
	dr.SizeRatio = sizeAnomalyCheck(oldDir, newDir, oldFiles, newFiles)
	if dr.SizeRatio > thresholds.CodeVolumeRatio {
		dr.Findings = append(dr.Findings, scanner.Finding{
			Severity:    scanner.SeverityHigh,
			Category:    "version-diff:size-anomaly",
			Description: "New version is significantly larger than previous version",
		})
	}

	// C. Sensitive file changes
	sensChanged, sensFindings := sensitiveFileChanges(ecosystem, modified, added, extraSensitive)
	dr.SensitiveChanges = sensChanged
	dr.Findings = append(dr.Findings, sensFindings...)

	// D. Entropy analysis
	dr.MaxEntropyDelta = entropyAnalysis(oldDir, newDir, modified, added, entropySampleBytes, thresholds.EntropyDelta, &dr.Findings)

	// E. New dependency detection
	newDeps, depFindings := newDependencyDetection(ecosystem, oldDir, newDir)
	dr.NewDependencies = newDeps
	dr.Findings = append(dr.Findings, depFindings...)

	return dr
}

// walkDir returns a list of file paths (relative to dir).
func walkDir(dir string) []string {
	var files []string
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		files = append(files, rel)
		return nil
	})
	return files
}

// fileInventoryDiff compares file lists and checks content differences.
func fileInventoryDiff(oldDir, newDir string, oldFiles, newFiles []string) (added, removed, modified []string) {
	oldSet := toSet(oldFiles)
	newSet := toSet(newFiles)

	for _, f := range newFiles {
		if !oldSet[f] {
			added = append(added, f)
		}
	}
	for _, f := range oldFiles {
		if !newSet[f] {
			removed = append(removed, f)
		}
	}
	// Files present in both — check content hash
	for _, f := range newFiles {
		if oldSet[f] {
			oldHash := fileHash(filepath.Join(oldDir, f))
			newHash := fileHash(filepath.Join(newDir, f))
			if oldHash != newHash {
				modified = append(modified, f)
			}
		}
	}
	return
}

// sizeAnomalyCheck computes the ratio of new total size to old total size.
func sizeAnomalyCheck(oldDir, newDir string, oldFiles, newFiles []string) float64 {
	oldSize := totalSize(oldDir, oldFiles)
	newSize := totalSize(newDir, newFiles)
	if oldSize == 0 {
		if newSize == 0 {
			return 1.0
		}
		return float64(newSize) // old is empty, treat as very large ratio
	}
	return float64(newSize) / float64(oldSize)
}

// sensitiveFileChanges checks for modifications to ecosystem-specific sensitive files.
func sensitiveFileChanges(ecosystem scanner.Ecosystem, modified, added []string, extraPatterns []string) (changed []string, findings []scanner.Finding) {
	patterns := builtinSensitivePatterns[ecosystem]
	patterns = append(patterns, extraPatterns...)

	checkFiles := append([]string{}, modified...)
	checkFiles = append(checkFiles, added...)

	for _, f := range checkFiles {
		base := filepath.Base(f)
		for _, pattern := range patterns {
			matched, _ := filepath.Match(pattern, base)
			if matched {
				changed = append(changed, f)
				// Install hooks are critical; MSBuild metadata is medium
				// (standard in NuGet packages); other sensitive files are high.
				sev := scanner.SeverityHigh
				if isInstallHook(ecosystem, base) {
					sev = scanner.SeverityCritical
				} else if isMSBuildMetadata(ecosystem, base) {
					sev = scanner.SeverityMedium
				}
				findings = append(findings, scanner.Finding{
					Severity:    sev,
					Category:    "version-diff:sensitive-file",
					Description: "Sensitive file added or modified in new version",
					Location:    f,
				})
				break // don't double-count same file
			}
		}
	}
	return
}

// isMSBuildMetadata returns true if the file is a standard NuGet MSBuild metadata file
// (.targets, .props). These are present in virtually every NuGet package and change
// between versions as a matter of course — they are NOT executable install hooks.
func isMSBuildMetadata(ecosystem scanner.Ecosystem, base string) bool {
	if ecosystem != scanner.EcosystemNuGet {
		return false
	}
	lower := strings.ToLower(base)
	return strings.HasSuffix(lower, ".targets") || strings.HasSuffix(lower, ".props")
}

// isInstallHook returns true if the filename is an install-time hook for the ecosystem.
func isInstallHook(ecosystem scanner.Ecosystem, base string) bool {
	lower := strings.ToLower(base)
	switch ecosystem {
	case scanner.EcosystemPyPI:
		return lower == "setup.py" || strings.HasSuffix(lower, ".pth")
	case scanner.EcosystemNPM:
		return strings.HasPrefix(lower, "preinstall") || strings.HasPrefix(lower, "postinstall") || lower == "install"
	case scanner.EcosystemNuGet:
		return lower == "install.ps1" || lower == "init.ps1"
	case scanner.EcosystemRubyGems:
		return lower == "extconf.rb"
	default:
		return false
	}
}

// entropyAnalysis checks for high-entropy additions in modified/added files.
// Returns the maximum entropy delta found.
func entropyAnalysis(oldDir, newDir string, modified, added []string, sampleBytes int, deltaThreshold float64, findings *[]scanner.Finding) float64 {
	var maxDelta float64

	for _, f := range added {
		if isBinaryExtension(f) {
			continue
		}
		data := readSample(filepath.Join(newDir, f), sampleBytes)
		ent := shannonEntropy(data)
		if ent > 6.0 {
			if ent > maxDelta {
				maxDelta = ent
			}
			*findings = append(*findings, scanner.Finding{
				Severity:    scanner.SeverityHigh,
				Category:    "version-diff:high-entropy",
				Description: "New file with high entropy (possible obfuscated/packed code)",
				Location:    f,
			})
		}
	}

	for _, f := range modified {
		if isBinaryExtension(f) {
			continue
		}
		oldData := readSample(filepath.Join(oldDir, f), sampleBytes)
		newData := readSample(filepath.Join(newDir, f), sampleBytes)
		oldEnt := shannonEntropy(oldData)
		newEnt := shannonEntropy(newData)
		delta := newEnt - oldEnt
		if delta > maxDelta {
			maxDelta = delta
		}
		if delta > deltaThreshold {
			*findings = append(*findings, scanner.Finding{
				Severity:    scanner.SeverityHigh,
				Category:    "version-diff:entropy-increase",
				Description: "Significant entropy increase in modified file",
				Location:    f,
			})
		}
	}

	return maxDelta
}

// shannonEntropy calculates Shannon entropy (bits/byte) for a byte slice.
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// newDependencyDetection parses ecosystem metadata to find newly added dependencies.
func newDependencyDetection(ecosystem scanner.Ecosystem, oldDir, newDir string) (newDeps []string, findings []scanner.Finding) {
	oldDeps := parseDependencies(ecosystem, oldDir)
	newDepsAll := parseDependencies(ecosystem, newDir)

	oldSet := toSet(oldDeps)
	for _, d := range newDepsAll {
		if !oldSet[d] {
			newDeps = append(newDeps, d)
		}
	}

	if len(newDeps) > 0 {
		findings = append(findings, scanner.Finding{
			Severity:    scanner.SeverityMedium,
			Category:    "version-diff:new-dependency",
			Description: "New dependencies added in this version",
			Location:    strings.Join(newDeps, ", "),
		})
	}
	return
}

// parseDependencies extracts dependency names from ecosystem-specific metadata files.
func parseDependencies(ecosystem scanner.Ecosystem, dir string) []string {
	switch ecosystem {
	case scanner.EcosystemNPM:
		return parseNPMDeps(dir)
	case scanner.EcosystemPyPI:
		return parsePyPIDeps(dir)
	case scanner.EcosystemGo:
		return parseGoDeps(dir)
	default:
		return nil
	}
}

// parseNPMDeps reads package.json and returns dependency names.
func parseNPMDeps(dir string) []string {
	data, err := os.ReadFile(findFile(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	var deps []string
	for name := range pkg.Dependencies {
		deps = append(deps, name)
	}
	for name := range pkg.DevDependencies {
		deps = append(deps, name)
	}
	return deps
}

// parsePyPIDeps reads setup.cfg or pyproject.toml for install_requires / dependencies.
func parsePyPIDeps(dir string) []string {
	// Try setup.cfg first
	if deps := parsePyPISetupCfg(dir); len(deps) > 0 {
		return deps
	}
	// Try pyproject.toml
	return parsePyPIPyproject(dir)
}

func parsePyPISetupCfg(dir string) []string {
	data, err := os.ReadFile(findFile(dir, "setup.cfg"))
	if err != nil {
		return nil
	}
	var deps []string
	inRequires := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "install_requires") {
			inRequires = true
			continue
		}
		if inRequires {
			if trimmed == "" || (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")) {
				break
			}
			dep := strings.FieldsFunc(trimmed, func(r rune) bool {
				return r == '>' || r == '<' || r == '=' || r == '!' || r == '~' || r == ';' || r == '['
			})[0]
			dep = strings.TrimSpace(dep)
			if dep != "" {
				deps = append(deps, dep)
			}
		}
	}
	return deps
}

func parsePyPIPyproject(dir string) []string {
	data, err := os.ReadFile(findFile(dir, "pyproject.toml"))
	if err != nil {
		return nil
	}
	var deps []string
	inDeps := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "dependencies = [" || strings.HasPrefix(trimmed, "dependencies = [") {
			inDeps = true
			continue
		}
		if inDeps {
			if trimmed == "]" {
				break
			}
			// Extract package name from "package>=1.0",
			dep := strings.Trim(trimmed, `",' `)
			dep = strings.FieldsFunc(dep, func(r rune) bool {
				return r == '>' || r == '<' || r == '=' || r == '!' || r == '~' || r == ';' || r == '['
			})[0]
			dep = strings.TrimSpace(dep)
			if dep != "" {
				deps = append(deps, dep)
			}
		}
	}
	return deps
}

// parseGoDeps reads go.mod require block.
func parseGoDeps(dir string) []string {
	data, err := os.ReadFile(findFile(dir, "go.mod"))
	if err != nil {
		return nil
	}
	var deps []string
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "require (" {
			inRequire = true
			continue
		}
		if inRequire {
			if trimmed == ")" {
				break
			}
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				deps = append(deps, parts[0])
			}
		}
		// Single-line require
		if matched, _ := regexp.MatchString(`^require\s+\S+`, trimmed); matched {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				deps = append(deps, parts[1])
			}
		}
	}
	return deps
}

// findFile searches for a file by name within dir (first level or nested).
func findFile(dir, name string) string {
	// Check top-level first
	direct := filepath.Join(dir, name)
	if _, err := os.Stat(direct); err == nil {
		return direct
	}
	// Search one level of nesting (e.g., package-1.0.0/package.json)
	var found string
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Base(path) == name && found == "" {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if found != "" {
		return found
	}
	return direct // return the direct path (will fail with "file not found" on read)
}

// --- Helpers ---

// builtinSensitivePatterns lists sensitive filenames per ecosystem.
var builtinSensitivePatterns = map[scanner.Ecosystem][]string{
	scanner.EcosystemPyPI:     {"setup.py", "setup.cfg", "*.pth", "__init__.py", "pyproject.toml"},
	scanner.EcosystemNPM:      {"package.json", "preinstall*", "postinstall*", "install*"},
	scanner.EcosystemNuGet:    {"*.targets", "*.props", "install.ps1", "init.ps1"},
	scanner.EcosystemMaven:    {"pom.xml", "*.sh"},
	scanner.EcosystemRubyGems: {"extconf.rb", "Rakefile"},
	scanner.EcosystemGo:       {"go.mod"},
}

// knownBinaryExtensions are skipped during entropy analysis.
var knownBinaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".class": true, ".pyc": true, ".pyo": true,
	".so": true, ".dll": true, ".dylib": true,
	".ico": true, ".bmp": true, ".tiff": true,
	".wasm": true,
}

func isBinaryExtension(path string) bool {
	return knownBinaryExtensions[strings.ToLower(filepath.Ext(path))]
}

func readSample(path string, sampleBytes int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if sampleBytes <= 0 {
		data, _ := io.ReadAll(f)
		return data
	}
	buf := make([]byte, sampleBytes)
	n, _ := f.Read(buf)
	return buf[:n]
}

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func totalSize(dir string, files []string) int64 {
	var total int64
	for _, f := range files {
		info, err := os.Stat(filepath.Join(dir, f))
		if err == nil {
			total += info.Size()
		}
	}
	return total
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
