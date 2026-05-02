package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestEngine_Evaluate_DBOverride_AllowsMalicious(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'false positive', 'test', ?, 0)`, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Contains(t, result.Reason, "policy override")
}

func TestEngine_Evaluate_RevokedOverride_StillBlocks(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked, revoked_at)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'false positive', 'test', ?, 1, ?)`, now, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestEngine_Evaluate_PackageScopeOverride_AllowsAnyVersion(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'requests', '', 'package', 'known safe package', 'test', ?, 0)`, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "9.99.99",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionAllow, result.Action)
}

func TestEngine_Evaluate_ExpiredDBOverride_StillBlocks(t *testing.T) {
	db := setupTestDB(t)

	past := time.Now().UTC().Add(-1 * time.Hour)
	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, expires_at, revoked)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'expired fp', 'test', ?, ?, 0)`, now, past)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestEngine_HasOverride_PackageScope_MatchesAnyVersion(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'vitest', '', 'package', 'legitimate', 'test', ?, 0)`, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{}, db)

	// Name-only call (no version) — must match the package-scoped override.
	assert.True(t, engine.HasOverride(context.Background(), scanner.EcosystemNPM, "vitest", ""))
	// Specific version — must also match (package-scope covers all versions).
	assert.True(t, engine.HasOverride(context.Background(), scanner.EcosystemNPM, "vitest", "1.0.0"))
	// Different package — must not match.
	assert.False(t, engine.HasOverride(context.Background(), scanner.EcosystemNPM, "lodsah", ""))
}

func TestEngine_HasOverride_VersionScope_DoesNotMatchNameOnly(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'fp', 'test', ?, 0)`, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{}, db)

	// Name-only call must NOT see a version-scoped override.
	assert.False(t, engine.HasOverride(context.Background(), scanner.EcosystemPyPI, "requests", ""))
	// Matching version — must match.
	assert.True(t, engine.HasOverride(context.Background(), scanner.EcosystemPyPI, "requests", "2.32.3"))
	// Different version — must not match.
	assert.False(t, engine.HasOverride(context.Background(), scanner.EcosystemPyPI, "requests", "2.31.0"))
}

func TestEngine_HasOverride_RevokedOverride_DoesNotMatch(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked, revoked_at)
		 VALUES ('npm', 'vitest', '', 'package', 'legitimate', 'test', ?, 1, ?)`, now, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{}, db)

	assert.False(t, engine.HasOverride(context.Background(), scanner.EcosystemNPM, "vitest", ""))
}

func TestEngine_HasOverride_NilDB_ReturnsFalse(t *testing.T) {
	engine := policy.NewEngine(policy.EngineConfig{}, nil)
	assert.False(t, engine.HasOverride(context.Background(), scanner.EcosystemNPM, "vitest", ""))
}

func TestEngine_Evaluate_NoDB_FallsBackToStaticAllowlist(t *testing.T) {
	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
		Allowlist:           []string{"pypi:requests:==2.32.3"},
	}, nil)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Contains(t, result.Reason, "allowlist")
}
