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
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(`INSERT INTO threat_feed (sha256, ecosystem, package_name, version, reported_at)
        VALUES ('abc123', 'pypi', 'evil-package', '1.0.0', datetime('now'))`)
	require.NoError(t, err)

	s := NewThreatFeedChecker(db, true)
	result, err := s.Scan(context.Background(), scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		SHA256:    "abc123",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.Equal(t, float32(1.0), result.Confidence)
}

func TestThreatFeedChecker_UnknownHash_ReturnsClean(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	s := NewThreatFeedChecker(db, true)
	result, err := s.Scan(context.Background(), scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		SHA256:    "unknown-hash",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

// TestThreatFeedChecker_EmptyFeed_ReturnsClean pins the deliberate fail-open: an
// empty feed still yields CLEAN with full confidence. HealthCheck reports the
// same state as unhealthy, but the verdict must not change until ADR-020 is
// decided — see docs/adr/ADR-020-threat-feed-empty-verdict.md.
func TestThreatFeedChecker_EmptyFeed_ReturnsClean(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	s := NewThreatFeedChecker(db, true)
	result, err := s.Scan(context.Background(), scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		SHA256:    "any-hash",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Equal(t, float32(1.0), result.Confidence)
}

func TestThreatFeedChecker_HealthCheck_PopulatedFeed_ReturnsNil(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(`INSERT INTO threat_feed (sha256, ecosystem, package_name, version, reported_at)
        VALUES ('abc123', 'pypi', 'evil-package', '1.0.0', datetime('now'))`)
	require.NoError(t, err)

	s := NewThreatFeedChecker(db, true)
	assert.NoError(t, s.HealthCheck(context.Background()))
}

func TestThreatFeedChecker_HealthCheck_EmptyFeedEnabled_ReturnsError(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	s := NewThreatFeedChecker(db, true)
	err = s.HealthCheck(context.Background())

	require.Error(t, err, "a configured feed with no entries detects nothing and must not report healthy")
	assert.ErrorIs(t, err, ErrFeedEmpty)
	// GET /api/v1/health is unauthenticated and renders this text verbatim. It must
	// stay neutral: naming the consequence there would tell an anonymous caller
	// exactly when the known-malicious-hash layer is down. The explanation lives in
	// docs/scanners.md and in the (non-public) log lines.
	assert.Equal(t, "threat feed empty", err.Error())
	assert.NotContains(t, err.Error(), "CLEAN")
}

func TestThreatFeedChecker_HealthCheck_FeedDisabled_ReturnsNil(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// The checker is registered unconditionally, so an empty table is the normal
	// state on every deployment running threat_feed.enabled: false. Reporting
	// that as unhealthy would be the cry-wolf failure this guard exists to stop.
	s := NewThreatFeedChecker(db, false)
	assert.NoError(t, s.HealthCheck(context.Background()))
}

func TestThreatFeedChecker_HealthCheck_DBUnavailable_ReturnsWrappedError(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	require.NoError(t, db.Close())

	s := NewThreatFeedChecker(db, true)
	err = s.HealthCheck(context.Background())

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrFeedEmpty, "an unreadable table must not be reported as an empty one")
	assert.Contains(t, err.Error(), "builtin-threat-feed: probing threat feed entries")
}
