package builtin

import (
	"context"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThreatFeedChecker_KnownMalicious_ReturnsMalicious(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(`INSERT INTO threat_feed (sha256, ecosystem, package_name, version, reported_at)
        VALUES ('abc123', 'pypi', 'evil-package', '1.0.0', datetime('now'))`)
	require.NoError(t, err)

	s := NewThreatFeedChecker(db)
	result, err := s.Scan(context.Background(), scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		SHA256:    "abc123",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.Equal(t, float32(1.0), result.Confidence)
}

func TestThreatFeedChecker_UnknownHash_ReturnsClean(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	s := NewThreatFeedChecker(db)
	result, err := s.Scan(context.Background(), scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		SHA256:    "unknown-hash",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestThreatFeedChecker_EmptyFeed_ReturnsClean(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	s := NewThreatFeedChecker(db)
	result, err := s.Scan(context.Background(), scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		SHA256:    "any-hash",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}
