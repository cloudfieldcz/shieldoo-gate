package builtin_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sha256OfFile is a test helper that computes the hex SHA256 of a file.
func sha256OfFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestHashVerifier_MatchingHash_ReturnsClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.tar.gz")
	require.NoError(t, os.WriteFile(path, []byte("legitimate content"), 0644))

	s := builtin.NewHashVerifier()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pkg-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "pkg",
		Version:   "1.0.0",
		LocalPath: path,
		SHA256:    sha256OfFile(t, path),
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Empty(t, result.Findings)
}

func TestHashVerifier_MismatchedHash_ReturnsMalicious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tampered.tar.gz")
	require.NoError(t, os.WriteFile(path, []byte("tampered content"), 0644))

	s := builtin.NewHashVerifier()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pkg-1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "pkg",
		Version:   "1.0.0",
		LocalPath: path,
		SHA256:    "0000000000000000000000000000000000000000000000000000000000000000",
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.NotEmpty(t, result.Findings)
}

func TestHashVerifier_EmptyExpectedHash_ReturnsClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unknown.tar.gz")
	require.NoError(t, os.WriteFile(path, []byte("some content"), 0644))

	s := builtin.NewHashVerifier()
	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pkg-1.0.0",
		Ecosystem: scanner.EcosystemNPM,
		Name:      "pkg",
		Version:   "1.0.0",
		LocalPath: path,
		SHA256:    "", // no expected hash provided
	})

	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.InDelta(t, 0.5, result.Confidence, 0.001)
}

func TestHashVerifier_SupportedEcosystems_All(t *testing.T) {
	s := builtin.NewHashVerifier()
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
