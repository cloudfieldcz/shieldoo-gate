package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/license"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
	"github.com/cloudfieldcz/shieldoo-gate/internal/sbom"
)

// newLicenseEngine creates a policy engine with license evaluation wired up.
func newLicenseEngine(t *testing.T, blocked, warned []string, onSBOMError license.Action) (*policy.Engine, *config.GateDB, sbom.Storage) {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	tmpDir := t.TempDir()
	blobs, err := local.NewLocalCacheStore(tmpDir, 1)
	require.NoError(t, err)

	sbomStore := sbom.NewStorage(db, blobs, "")

	resolver := license.NewResolver(db, license.ResolverConfig{
		Global: license.Policy{
			Blocked: blocked,
			Warned:  warned,
			Source:  "global",
		},
	})

	if onSBOMError == "" {
		onSBOMError = license.ActionAllow
	}

	engine := policy.NewEngine(defaultEngineConfig(), db,
		policy.WithLicenseEvaluator(
			license.NewEvaluator(),
			resolver,
			sbomStore,
			onSBOMError,
		),
	)

	return engine, db, sbomStore
}

// seedArtifactWithLicenses inserts an artifact row and SBOM metadata with the given licenses.
func seedArtifactWithLicenses(t *testing.T, db *config.GateDB, sbomStore sbom.Storage, artifactID string, licenses []string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES (?, 'npm', 'test', '1.0', 'u', 's', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '/tmp')`, artifactID)
	require.NoError(t, err)

	if len(licenses) > 0 {
		err = sbomStore.WriteLicensesOnly(context.Background(), artifactID, licenses, "test")
		require.NoError(t, err)
	}
}

func TestEvaluateLicensesOnly_BlockedLicense_ReturnsBlock(t *testing.T) {
	engine, db, store := newLicenseEngine(t, []string{"MIT"}, nil, "")
	seedArtifactWithLicenses(t, db, store, "npm:chalk:5.4.1", []string{"MIT"})

	result := engine.EvaluateLicensesOnly(context.Background(), "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "MIT")
}

func TestEvaluateLicensesOnly_AllowedLicense_ReturnsAllow(t *testing.T) {
	engine, db, store := newLicenseEngine(t, []string{"GPL-3.0-only"}, nil, "")
	seedArtifactWithLicenses(t, db, store, "npm:chalk:5.4.1", []string{"MIT"})

	result := engine.EvaluateLicensesOnly(context.Background(), "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionAllow, result.Action)
}

func TestEvaluateLicensesOnly_WarnedLicense_ReturnsAllowWithWarnings(t *testing.T) {
	engine, db, store := newLicenseEngine(t, nil, []string{"MIT"}, "")
	seedArtifactWithLicenses(t, db, store, "npm:chalk:5.4.1", []string{"MIT"})

	result := engine.EvaluateLicensesOnly(context.Background(), "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.NotEmpty(t, result.Warnings)
	assert.Contains(t, result.Warnings[0], "MIT")
}

func TestEvaluateLicensesOnly_NoSBOM_OnSBOMErrorBlock_ReturnsBlock(t *testing.T) {
	engine, db, _ := newLicenseEngine(t, []string{"MIT"}, nil, license.ActionBlock)
	// Seed artifact WITHOUT SBOM metadata.
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES ('npm:unknown:1.0', 'npm', 'unknown', '1.0', 'u', 's', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '/tmp')`)
	require.NoError(t, err)

	result := engine.EvaluateLicensesOnly(context.Background(), "npm:unknown:1.0")
	assert.Equal(t, policy.ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "SBOM unavailable")
}

func TestEvaluateLicensesOnly_NoSBOM_OnSBOMErrorAllow_ReturnsAllow(t *testing.T) {
	engine, db, _ := newLicenseEngine(t, []string{"MIT"}, nil, license.ActionAllow)
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES ('npm:unknown:1.0', 'npm', 'unknown', '1.0', 'u', 's', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '/tmp')`)
	require.NoError(t, err)

	result := engine.EvaluateLicensesOnly(context.Background(), "npm:unknown:1.0")
	assert.Equal(t, policy.ActionAllow, result.Action)
}

func TestEvaluateLicensesOnly_DisabledPolicy_ReturnsAllow(t *testing.T) {
	// Engine without license evaluator wired = disabled.
	engine := policy.NewEngine(defaultEngineConfig(), nil)

	result := engine.EvaluateLicensesOnly(context.Background(), "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionAllow, result.Action)
}

func TestEvaluateLicensesOnly_CanceledContext_ReturnsAllow(t *testing.T) {
	// When the HTTP request context is canceled (client disconnected mid
	// flight), the DB query returns context.Canceled. The previous fail-
	// closed handler would mark the artifact BLOCKED and append a
	// LICENSE_BLOCKED audit entry even though no one is listening. We now
	// treat canceled contexts as "client went away — no enforcement needed".
	engine, db, store := newLicenseEngine(t, []string{"GPL-3.0"}, nil, "")
	seedArtifactWithLicenses(t, db, store, "npm:chalk:5.4.1", []string{"MIT"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := engine.EvaluateLicensesOnly(ctx, "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionAllow, result.Action,
		"canceled context must not trigger fail-closed block")
}

func TestEvaluateLicensesOnly_DeadlineExceeded_ReturnsAllow(t *testing.T) {
	// Same rationale as above, but for context.DeadlineExceeded (slow DB
	// under load while a pipeline timeout expires).
	engine, db, store := newLicenseEngine(t, []string{"GPL-3.0"}, nil, "")
	seedArtifactWithLicenses(t, db, store, "npm:chalk:5.4.1", []string{"MIT"})

	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	result := engine.EvaluateLicensesOnly(ctx, "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionAllow, result.Action,
		"deadline-exceeded context must not trigger fail-closed block")
}

// seedNamedArtifact inserts an artifact row with the given ecosystem/name/version
// (the shared seedArtifactWithLicenses helper hardcodes those columns, which
// breaks per-project override tests that key on real package identity).
func seedNamedArtifact(t *testing.T, db *config.GateDB, store sbom.Storage, id, ecosystem, name, version string, licenses []string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES (?, ?, ?, ?, 'u', 's', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '/tmp')`, id, ecosystem, name, version)
	require.NoError(t, err)
	if len(licenses) > 0 {
		require.NoError(t, store.WriteLicensesOnly(context.Background(), id, licenses, "test"))
	}
}

func seedProject(t *testing.T, db *config.GateDB, label string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO projects (label, display_name, description, created_at, created_via, enabled)
		 VALUES (?, '', '', ?, 'test', 1)`, label, time.Now().UTC())
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func TestEvaluateLicensesOnly_ProjectAllowOverride_BypassesLicenseBlock(t *testing.T) {
	engine, db, store := newLicenseEngine(t, []string{"GPL-3.0-only"}, nil, "")
	seedNamedArtifact(t, db, store, "npm:chalk:5.4.1", "npm", "chalk", "5.4.1", []string{"GPL-3.0-only"})

	projectID := seedProject(t, db, "acme")
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'chalk', '', 'package', 'allow', ?, 'legal approved', 'test', ?, 0)`,
		projectID, time.Now().UTC())
	require.NoError(t, err)

	ctx := project.WithContext(context.Background(), &project.Project{ID: projectID, Label: "acme"})
	result := engine.EvaluateLicensesOnly(ctx, "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionAllow, result.Action,
		"per-project allow override must bypass license block")
}

func TestEvaluateLicensesOnly_ProjectDenyOverride_BlocksAllowedLicense(t *testing.T) {
	engine, db, store := newLicenseEngine(t, []string{"GPL-3.0-only"}, nil, "")
	seedNamedArtifact(t, db, store, "npm:chalk:5.4.1", "npm", "chalk", "5.4.1", []string{"MIT"})

	projectID := seedProject(t, db, "acme")
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'chalk', '', 'package', 'deny', ?, 'banned in acme', 'test', ?, 0)`,
		projectID, time.Now().UTC())
	require.NoError(t, err)

	ctx := project.WithContext(context.Background(), &project.Project{ID: projectID, Label: "acme"})
	result := engine.EvaluateLicensesOnly(ctx, "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionBlock, result.Action)
	assert.Contains(t, result.Reason, "deny")
}

func TestEvaluateLicensesOnly_NoProjectContext_DoesNotApplyProjectOverride(t *testing.T) {
	// Background re-evaluator has no project on context — per-project deny
	// overrides must NOT block here, only global allow / license policy run.
	engine, db, store := newLicenseEngine(t, []string{"GPL-3.0-only"}, nil, "")
	seedNamedArtifact(t, db, store, "npm:chalk:5.4.1", "npm", "chalk", "5.4.1", []string{"MIT"})

	projectID := seedProject(t, db, "acme")
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, kind, project_id, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'chalk', '', 'package', 'deny', ?, 'banned in acme', 'test', ?, 0)`,
		projectID, time.Now().UTC())
	require.NoError(t, err)

	// No project on context.
	result := engine.EvaluateLicensesOnly(context.Background(), "npm:chalk:5.4.1")
	assert.Equal(t, policy.ActionAllow, result.Action,
		"per-project deny must not apply when no project is on context (re-evaluator path)")
}
