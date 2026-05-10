package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestMigration036_BackfillsLicenseOverrides verifies that an active global
// "manual release" override is mirrored into a per-project allow row for every
// existing project, and that re-running the migration body is idempotent.
func TestMigration036_BackfillsLicenseOverrides(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	now := time.Now().UTC()

	// Add two extra projects on top of the seeded 'default' (id=1).
	_, err = db.Exec(
		`INSERT INTO projects (id, label, display_name, created_at, created_via, enabled)
		 VALUES (101, 'p1', 'P1', ?, 'seed', 1)`, now)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO projects (id, label, display_name, created_at, created_via, enabled)
		 VALUES (102, 'p2', 'P2', ?, 'seed', 1)`, now)
	require.NoError(t, err)

	// Seed an active global manual-release override on a license-flavoured
	// package. Mirrors what handleReleaseArtifact wrote for license blocks
	// before this migration shipped.
	_, err = db.Exec(
		`INSERT INTO policy_overrides
		 (ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'gpltool', '1.0', 'version', NULL, 'allow', 'manual release', 'op@example.com', ?, 0)`,
		now)
	require.NoError(t, err)

	// Re-run migration 036 manually (its body is in the embed.FS already; the
	// initial InitDB applied it once on a DB that had no projects beyond the
	// 'default' seed and no globals to mirror, so most rows landed only after
	// our seed above. The simplest reset is to read the body and execute it).
	migrations, err := readMigrations(sqliteMigrationFS, "migrations/sqlite")
	require.NoError(t, err)
	// Migrations are sorted by filename, and 036 is the last one in the list at
	// the time of writing. We re-run only that body so we don't perturb the
	// rest of the schema.
	var migration036 string
	for _, m := range migrations {
		if containsMarker(m, "036_license_overrides_per_project") || containsMarker(m, "036: was global manual release") {
			migration036 = m
			break
		}
	}
	require.NotEmpty(t, migration036, "migration 036 body not found in embed.FS")

	_, err = db.Exec(migration036)
	require.NoError(t, err)

	// Backfilled rows: one per project (default + p1 + p2 = 3).
	var n int
	require.NoError(t, db.Get(&n,
		`SELECT COUNT(*) FROM policy_overrides
		  WHERE name = 'gpltool' AND project_id IS NOT NULL AND revoked = 0`))
	require.Equal(t, 3, n,
		"expected 3 per-project rows (one per project incl. seeded default), got %d", n)

	// All migrated rows are tagged.
	var tagged int
	require.NoError(t, db.Get(&tagged,
		`SELECT COUNT(*) FROM policy_overrides
		  WHERE name = 'gpltool' AND created_by = 'migration:036'`))
	require.Equal(t, 3, tagged, "all backfilled rows must carry created_by='migration:036'")

	// Original global stays.
	var global int
	require.NoError(t, db.Get(&global,
		`SELECT COUNT(*) FROM policy_overrides
		  WHERE name = 'gpltool' AND project_id IS NULL AND revoked = 0`))
	require.Equal(t, 1, global, "global override must stay (audit trail)")

	// Idempotency: re-run must not duplicate.
	_, err = db.Exec(migration036)
	require.NoError(t, err)
	require.NoError(t, db.Get(&n,
		`SELECT COUNT(*) FROM policy_overrides
		  WHERE name = 'gpltool' AND project_id IS NOT NULL AND revoked = 0`))
	require.Equal(t, 3, n, "idempotent re-run produced %d rows, want 3", n)
}

// TestMigration036_DoesNotMigrateRevokedGlobals verifies that a revoked global
// is NOT migrated (only active 'manual release' rows are mirrored).
func TestMigration036_DoesNotMigrateRevokedGlobals(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO projects (id, label, display_name, created_at, created_via, enabled)
		 VALUES (201, 'revoked-test', 'Revoked Test', ?, 'seed', 1)`, now)
	require.NoError(t, err)

	// Active global manual-release: should mirror.
	_, err = db.Exec(
		`INSERT INTO policy_overrides
		 (ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, revoked)
		 VALUES ('npm', 'active-pkg', '1.0', 'version', NULL, 'allow', 'manual release', 'op', ?, 0)`,
		now)
	require.NoError(t, err)

	// Revoked global manual-release: should NOT mirror.
	_, err = db.Exec(
		`INSERT INTO policy_overrides
		 (ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, revoked, revoked_at)
		 VALUES ('npm', 'revoked-pkg', '2.0', 'version', NULL, 'allow', 'manual release', 'op', ?, 1, ?)`,
		now, now)
	require.NoError(t, err)

	// Re-run migration 036.
	migrations, err := readMigrations(sqliteMigrationFS, "migrations/sqlite")
	require.NoError(t, err)
	var migration036 string
	for _, m := range migrations {
		if containsMarker(m, "036_license_overrides_per_project") || containsMarker(m, "036: was global manual release") {
			migration036 = m
			break
		}
	}
	require.NotEmpty(t, migration036)
	_, err = db.Exec(migration036)
	require.NoError(t, err)

	var activeMirrors, revokedMirrors int
	require.NoError(t, db.Get(&activeMirrors,
		`SELECT COUNT(*) FROM policy_overrides
		  WHERE name = 'active-pkg' AND project_id = 201 AND revoked = 0`))
	require.NoError(t, db.Get(&revokedMirrors,
		`SELECT COUNT(*) FROM policy_overrides
		  WHERE name = 'revoked-pkg' AND project_id = 201`))
	require.Equal(t, 1, activeMirrors, "active global must mirror to project")
	require.Equal(t, 0, revokedMirrors, "revoked global must NOT mirror")
}

// containsMarker reports whether the migration body contains the given
// substring. Used to find migration 036 by content rather than filename
// (readMigrations strips the path).
func containsMarker(body, marker string) bool {
	for i := 0; i+len(marker) <= len(body); i++ {
		if body[i:i+len(marker)] == marker {
			return true
		}
	}
	return false
}
