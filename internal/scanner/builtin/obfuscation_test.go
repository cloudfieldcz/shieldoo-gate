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

func writeCodeFile(t *testing.T, filename, content string) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, filename)
	require.NoError(t, os.WriteFile(full, []byte(content), 0644))
	return full
}

func TestObfuscationDetector_Base64Exec_ReturnsMalicious(t *testing.T) {
	path := writeCodeFile(t, "evil.py",
		`import base64
exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk="))
`)

	s := builtin.NewObfuscationDetector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "evil-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "evil",
		Version:   "1.0.0",
		LocalPath: path,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.InDelta(t, 0.9, result.Confidence, 0.001)
	assert.NotEmpty(t, result.Findings)
}

func TestObfuscationDetector_EvalAtob_ReturnsSuspicious(t *testing.T) {
	path := writeCodeFile(t, "evil.js",
		`eval(atob("Y29uc29sZS5sb2coImV2aWwiKQ=="))
`)

	s := builtin.NewObfuscationDetector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "evil-npm-1.0.0",
		Ecosystem: scanner.EcosystemNPM,
		Name:      "evil-npm",
		Version:   "1.0.0",
		LocalPath: path,
	})

	require.NoError(t, err)
	assert.True(t,
		result.Verdict == scanner.VerdictMalicious || result.Verdict == scanner.VerdictSuspicious,
		"expected MALICIOUS or SUSPICIOUS, got %s", result.Verdict,
	)
	assert.NotEmpty(t, result.Findings)
}

func TestObfuscationDetector_CleanCode_ReturnsClean(t *testing.T) {
	path := writeCodeFile(t, "main.py", `print("hello world")
`)

	s := builtin.NewObfuscationDetector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "clean-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "clean",
		Version:   "1.0.0",
		LocalPath: path,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestObfuscationDetector_SupportedEcosystems_All(t *testing.T) {
	s := builtin.NewObfuscationDetector()
	ecosystems := s.SupportedEcosystems()
	require.Len(t, ecosystems, 4)

	ecoSet := make(map[scanner.Ecosystem]bool)
	for _, e := range ecosystems {
		ecoSet[e] = true
	}
	assert.True(t, ecoSet[scanner.EcosystemPyPI])
	assert.True(t, ecoSet[scanner.EcosystemNPM])
	assert.True(t, ecoSet[scanner.EcosystemDocker])
	assert.True(t, ecoSet[scanner.EcosystemNuGet])
}
