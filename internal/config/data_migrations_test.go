package config

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigratePyPICanonicalNames_RewritesArtifactsAndCascadeTables sets up a
// SQLite database in the pre-migration state — a PyPI artifact with the wheel
// (underscore) form, plus rows in scan_results, artifact_status, audit_log,
// and policy_overrides referencing it — runs the migration, and verifies all
// rows now use the canonical (hyphen) form.
func TestMigratePyPICanonicalNames_RewritesArtifactsAndCascadeTables(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Wipe any data the data-migration writer may have applied for the empty
	// schema, then re-insert a row that simulates old (pre-migration) state.
	_, err = db.Exec(`DELETE FROM data_migrations`)
	require.NoError(t, err)

	const oldID = "pypi:strawberry_graphql:0.263.0:strawberry_graphql-0.263.0-py3-none-any.whl"
	now := time.Now().UTC()

	_, err = db.Exec(db.Rebind(`INSERT INTO artifacts
		(id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES (?, 'pypi', 'strawberry_graphql', '0.263.0', 'https://files.pythonhosted.org/x.whl', 'deadbeef', 100, ?, ?, '/tmp/x')`),
		oldID, now, now,
	)
	require.NoError(t, err)

	_, err = db.Exec(db.Rebind(`INSERT INTO artifact_status (artifact_id, status) VALUES (?, 'QUARANTINED')`), oldID)
	require.NoError(t, err)

	_, err = db.Exec(db.Rebind(`INSERT INTO scan_results
		(artifact_id, scanned_at, scanner_name, scanner_version, verdict, confidence, findings_json, duration_ms)
		VALUES (?, ?, 'osv', '1.0', 'CLEAN', 1.0, '[]', 50)`),
		oldID, now,
	)
	require.NoError(t, err)

	_, err = db.Exec(db.Rebind(`INSERT INTO audit_log (ts, event_type, artifact_id, reason)
		VALUES (?, 'QUARANTINED', ?, 'pre-migration row')`), now, oldID)
	require.NoError(t, err)

	_, err = db.Exec(db.Rebind(`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		VALUES ('pypi', 'strawberry_graphql', '0.263.0', 'version', 'manual release', 'test', ?, FALSE)`), now)
	require.NoError(t, err)

	// Run the migration we just un-tracked.
	require.NoError(t, runDataMigrations(db.DB))

	// Artifact row: id and name now canonical.
	var newID, newName string
	err = db.Get(&newID, db.Rebind(`SELECT id FROM artifacts WHERE ecosystem = 'pypi'`))
	require.NoError(t, err)
	assert.Equal(t, "pypi:strawberry-graphql:0.263.0:strawberry_graphql-0.263.0-py3-none-any.whl", newID)
	err = db.Get(&newName, db.Rebind(`SELECT name FROM artifacts WHERE ecosystem = 'pypi'`))
	require.NoError(t, err)
	assert.Equal(t, "strawberry-graphql", newName)

	// The old row is gone.
	var oldCount int
	err = db.Get(&oldCount, db.Rebind(`SELECT COUNT(*) FROM artifacts WHERE id = ?`), oldID)
	require.NoError(t, err)
	assert.Equal(t, 0, oldCount, "old artifact row still exists")

	// All cascade tables now point to the new id.
	for _, table := range []string{"scan_results", "artifact_status", "audit_log"} {
		var cnt int
		err = db.Get(&cnt, db.Rebind(`SELECT COUNT(*) FROM `+table+` WHERE artifact_id = ?`), newID)
		require.NoError(t, err, table)
		assert.GreaterOrEqual(t, cnt, 1, table+": no rows repointed to canonical id")

		var orphan int
		err = db.Get(&orphan, db.Rebind(`SELECT COUNT(*) FROM `+table+` WHERE artifact_id = ?`), oldID)
		require.NoError(t, err, table)
		assert.Equal(t, 0, orphan, table+": rows still reference old artifact_id")
	}

	// policy_overrides.name canonicalized.
	var ovrName string
	err = db.Get(&ovrName, db.Rebind(`SELECT name FROM policy_overrides WHERE ecosystem = 'pypi'`))
	require.NoError(t, err)
	assert.Equal(t, "strawberry-graphql", ovrName)
}

// TestMigratePyPICanonicalNames_Idempotent runs the migration twice and asserts
// the second pass is a no-op (no error, no double-rewrite).
func TestMigratePyPICanonicalNames_Idempotent(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// First InitDB already ran data migrations on an empty schema. Insert a
	// row that's already canonical and verify a re-run leaves it alone.
	now := time.Now().UTC()
	const id = "pypi:requests:2.32.3:requests-2.32.3-py3-none-any.whl"
	_, err = db.Exec(db.Rebind(`INSERT INTO artifacts
		(id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		VALUES (?, 'pypi', 'requests', '2.32.3', 'https://files.pythonhosted.org/x.whl', 'deadbeef', 100, ?, ?, '/tmp/x')`),
		id, now, now,
	)
	require.NoError(t, err)

	require.NoError(t, migratePyPICanonicalNames(context.Background(), db.DB))

	// Same id, same name, no orphan rows.
	var cnt int
	err = db.Get(&cnt, db.Rebind(`SELECT COUNT(*) FROM artifacts WHERE id = ?`), id)
	require.NoError(t, err)
	assert.Equal(t, 1, cnt)
}
