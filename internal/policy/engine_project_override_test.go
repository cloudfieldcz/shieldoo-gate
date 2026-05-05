package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withProject wraps ctx with a synthetic Project carrying the given ID/label.
func withProject(ctx context.Context, projectID int64, label string) context.Context {
	return project.WithContext(ctx, &project.Project{ID: projectID, Label: label})
}

func TestEngine_Evaluate_ProjectAllowOverride_AllowsBlockedScan(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now().UTC()

	// Insert project + per-project allow override.
	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('acme', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectID, err := res.LastInsertId()
	require.NoError(t, err)

	_, err = db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'left-pad', '', 'package', 'allow', ?, 'team approved', 'test', ?, 0)`,
		projectID, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:    scanner.VerdictMalicious,
		MinimumConfidence: 0.7,
	}, db)

	artifact := scanner.Artifact{Ecosystem: scanner.EcosystemNPM, Name: "left-pad", Version: "1.0.0"}
	scanResults := []scanner.ScanResult{{Verdict: scanner.VerdictMalicious, Confidence: 0.9}}

	ctx := withProject(context.Background(), projectID, "acme")
	result := engine.Evaluate(ctx, artifact, scanResults)
	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Contains(t, result.Reason, "policy override")
}

func TestEngine_Evaluate_ProjectAllowOverride_DoesNotLeakAcrossProjects(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now().UTC()

	// Two projects; only project A has an allow override for left-pad.
	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('acme', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectA, _ := res.LastInsertId()

	res, err = db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('beta', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectB, _ := res.LastInsertId()

	_, err = db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'left-pad', '', 'package', 'allow', ?, 'team approved', 'test', ?, 0)`,
		projectA, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:    scanner.VerdictMalicious,
		MinimumConfidence: 0.7,
	}, db)

	artifact := scanner.Artifact{Ecosystem: scanner.EcosystemNPM, Name: "left-pad", Version: "1.0.0"}
	scanResults := []scanner.ScanResult{{Verdict: scanner.VerdictMalicious, Confidence: 0.9}}

	// Project B should still be blocked.
	ctxB := withProject(context.Background(), projectB, "beta")
	resultB := engine.Evaluate(ctxB, artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, resultB.Action, "project B has no override — should still block")
}

func TestEngine_Evaluate_ProjectDenyOverride_BlocksAllowedPackage(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now().UTC()

	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('acme', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectID, _ := res.LastInsertId()

	_, err = db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'lodash', '', 'package', 'deny', ?, 'banned', 'test', ?, 0)`,
		projectID, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:    scanner.VerdictMalicious,
		MinimumConfidence: 0.7,
	}, db)

	artifact := scanner.Artifact{Ecosystem: scanner.EcosystemNPM, Name: "lodash", Version: "4.17.21"}
	// CLEAN scan — would normally pass.
	scanResults := []scanner.ScanResult{{Verdict: scanner.VerdictClean, Confidence: 0.9}}

	ctx := withProject(context.Background(), projectID, "acme")
	result := engine.Evaluate(ctx, artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "deny")
}

func TestEngine_Evaluate_ProjectDenyBeatsProjectAllow(t *testing.T) {
	db := setupTestDB(t)
	now := time.Now().UTC()

	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('acme', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectID, _ := res.LastInsertId()

	_, err = db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'requests', '', 'package', 'allow', ?, 'allow', 'test', ?, 0)`,
		projectID, now)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'requests', '', 'package', 'deny', ?, 'deny', 'test', ?, 0)`,
		projectID, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:    scanner.VerdictMalicious,
		MinimumConfidence: 0.7,
	}, db)

	artifact := scanner.Artifact{Ecosystem: scanner.EcosystemNPM, Name: "requests", Version: "1.0.0"}
	scanResults := []scanner.ScanResult{{Verdict: scanner.VerdictClean, Confidence: 0.9}}

	ctx := withProject(context.Background(), projectID, "acme")
	result := engine.Evaluate(ctx, artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, result.Action, "deny must beat allow within same project")
}

func TestEngine_Evaluate_ProjectAllowBeatsGlobalAllow(t *testing.T) {
	// Both global ALLOW and project ALLOW present — Evaluate behavior is the
	// same (Allow either way), but the override_id stamped should be the
	// project-scoped one. We assert the precedence indirectly via lookup in
	// HasOverride.
	db := setupTestDB(t)
	now := time.Now().UTC()

	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('acme', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectID, _ := res.LastInsertId()

	// Global allow first
	resG, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'foo', '', 'package', 'allow', NULL, 'global', 'test', ?, 0)`, now)
	require.NoError(t, err)
	globalID, _ := resG.LastInsertId()

	// Project allow second (more recent)
	resP, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'foo', '', 'package', 'allow', ?, 'project', 'test', ?, 0)`,
		projectID, now.Add(time.Second))
	require.NoError(t, err)
	projectAllowID, _ := resP.LastInsertId()

	engine := policy.NewEngine(policy.EngineConfig{}, db)

	ctx := withProject(context.Background(), projectID, "acme")
	gotID, ok := engine.HasOverride(ctx, scanner.EcosystemNPM, "foo", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, projectAllowID, gotID, "project-scoped allow should win over global allow")
	assert.NotEqual(t, globalID, gotID)

	// Without project context, only global allow matches.
	gotID, ok = engine.HasOverride(context.Background(), scanner.EcosystemNPM, "foo", "1.0.0")
	require.True(t, ok)
	assert.Equal(t, globalID, gotID, "no project context — global allow should match")
}

func TestEngine_Evaluate_ProjectDeny_OverridesEvenWhenLicensingDisabled(t *testing.T) {
	// Without a license evaluator wired the engine treats license enforcement
	// as off, but a project deny override must still block at Evaluate time.
	db := setupTestDB(t)
	now := time.Now().UTC()

	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('acme', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectID, _ := res.LastInsertId()

	_, err = db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'evil', '1.0.0', 'version', 'deny', ?, 'banned in this project', 'test', ?, 0)`,
		projectID, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:    scanner.VerdictMalicious,
		MinimumConfidence: 0.7,
	}, db)

	artifact := scanner.Artifact{Ecosystem: scanner.EcosystemPyPI, Name: "evil", Version: "1.0.0"}
	scanResults := []scanner.ScanResult{{Verdict: scanner.VerdictClean, Confidence: 0.9}}

	ctx := withProject(context.Background(), projectID, "acme")
	result := engine.Evaluate(ctx, artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, result.Action)

	// Different version should not trip the version-scoped override.
	artifact2 := scanner.Artifact{Ecosystem: scanner.EcosystemPyPI, Name: "evil", Version: "1.0.1"}
	result2 := engine.Evaluate(ctx, artifact2, scanResults)
	assert.Equal(t, policy.ActionAllow, result2.Action, "version-scope deny only matches exact version")
}

func TestEngine_HasOverride_ProjectDenyDoesNotMatch(t *testing.T) {
	// HasOverride is the ALLOW-only API used by the typosquat short-circuit.
	// A project DENY must not be reported as a typosquat allow.
	db := setupTestDB(t)
	now := time.Now().UTC()

	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES ('acme', '', '', ?, 'test', 1)`, now)
	require.NoError(t, err)
	projectID, _ := res.LastInsertId()

	_, err = db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'lodash', '', 'package', 'deny', ?, 'banned', 'test', ?, 0)`,
		projectID, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{}, db)
	ctx := withProject(context.Background(), projectID, "acme")

	gotID, ok := engine.HasOverride(ctx, scanner.EcosystemNPM, "lodash", "")
	assert.False(t, ok)
	assert.Equal(t, int64(0), gotID)
}
