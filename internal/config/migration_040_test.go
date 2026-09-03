package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// migrationBody returns the embedded SQLite migration whose text contains marker.
func migrationBody(t *testing.T, marker string) string {
	t.Helper()
	migrations, err := readMigrations(sqliteMigrationFS, "migrations/sqlite")
	require.NoError(t, err)
	for _, m := range migrations {
		if containsMarker(m, marker) {
			return m
		}
	}
	t.Fatalf("migration body containing %q not found in embed.FS", marker)
	return ""
}

// Every cve_ignores row created before ADR-021 carried the finding's version — the admin
// UI always sent it — while the predicate ignored it. Under version-aware matching those
// rows would silently narrow to a single version. Migration 040 nulls the column so each
// row keeps the per-package scope its author actually chose.
func TestMigration040_NullsPackageVersionOnEveryIgnore(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`INSERT INTO components (id, project_id, name, ecosystem, enabled)
	                  VALUES (1, 1, 'gate-image', 'go', 1)`)
	require.NoError(t, err)
	// One active row and one revoked row, both carrying a version, exactly as the admin
	// UI wrote them before this change.
	_, err = db.Exec(
		`INSERT INTO cve_ignores (id, component_id, cve_id, package_name, package_version,
		                          reason, created_by_email, revoked_at)
		 VALUES (1, 1, 'CVE-2026-1', 'stdlib',  '1.24.6', 'legacy active',  'ops@example.com', NULL),
		        (2, 1, 'CVE-2026-2', 'oras-go', '1.2.3',  'legacy revoked', 'ops@example.com', CURRENT_TIMESTAMP)`)
	require.NoError(t, err)

	_, err = db.Exec(migrationBody(t, "040_cve_ignores_preserve_per_package_scope"))
	require.NoError(t, err)

	var remaining int
	require.NoError(t, db.Get(&remaining,
		`SELECT COUNT(*) FROM cve_ignores WHERE package_version IS NOT NULL`))
	assert.Zero(t, remaining, "revoked rows are nulled too — the UI restore panel re-creates from them")

	// The rows themselves survive: this is a scope correction, not a cleanup.
	var total int
	require.NoError(t, db.Get(&total, `SELECT COUNT(*) FROM cve_ignores`))
	assert.Equal(t, 2, total)
}

// Re-running the whole migration set on an established DB must not disturb ignores
// created after the upgrade — the runner keys schema_migrations on the file index, so 040
// applies exactly once, but the body itself is also proven harmless to replay only in the
// sense that it is not replayed. This test pins the once-only behaviour.
func TestMigration040_AppliedOnce_LaterVersionPinnedIgnoreSurvivesRestart(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`INSERT INTO components (id, project_id, name, ecosystem, enabled)
	                  VALUES (1, 1, 'gate-image', 'go', 1)`)
	require.NoError(t, err)
	// An ignore an operator deliberately pinned after the upgrade.
	_, err = db.Exec(
		`INSERT INTO cve_ignores (id, component_id, cve_id, package_name, package_version,
		                          reason, created_by_email)
		 VALUES (1, 1, 'CVE-2026-3', 'stdlib', '1.24.6', 'bundled trivy', 'ops@example.com')`)
	require.NoError(t, err)

	// Simulate a restart: InitDB runs the migration set again against the same DB.
	require.NoError(t, runMigrations(db.DB, sqliteMigrationFS, "migrations/sqlite"))

	var version *string
	require.NoError(t, db.Get(&version, `SELECT package_version FROM cve_ignores WHERE id = 1`))
	require.NotNil(t, version, "a deliberately pinned ignore must survive a restart")
	assert.Equal(t, "1.24.6", *version)
}
