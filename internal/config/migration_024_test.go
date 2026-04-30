package config

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration024_AddsAIColumnsAndUniqueIndex(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	type col struct {
		Cid     int            `db:"cid"`
		Name    string         `db:"name"`
		Type    string         `db:"type"`
		Notnull int            `db:"notnull"`
		DfltVal sql.NullString `db:"dflt_value"`
		Pk      int            `db:"pk"`
	}
	var cols []col
	require.NoError(t, db.Select(&cols, "PRAGMA table_info(version_diff_results)"))

	wantNullable := map[string]bool{
		"ai_verdict":        true,
		"ai_confidence":     true,
		"ai_explanation":    true,
		"ai_model_used":     true,
		"ai_prompt_version": true,
		"ai_tokens_used":    true,
		"previous_version":  true,
		"files_added":       true,
		"files_removed":     true,
		"files_modified":    true,
		"size_ratio":        true,
		"max_entropy_delta": true,
	}

	got := map[string]bool{}
	for _, c := range cols {
		got[c.Name] = c.Notnull == 0
	}
	for name, expectNullable := range wantNullable {
		nullable, present := got[name]
		require.True(t, present, "column %s missing after migration 024", name)
		require.Equal(t, expectNullable, nullable, "column %s nullability mismatch", name)
	}
}

func TestMigration024_UniqueIndexEnforced(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'pypi', 'foo', '1.0', 'https://up/foo-1.0', 'h1', 100, datetime('now'), datetime('now'), '/tmp/a1'),
		        (?, 'pypi', 'foo', '0.9', 'https://up/foo-0.9', 'h2', 100, datetime('now', '-1 day'), datetime('now', '-1 day'), '/tmp/a2')`,
		"art-new", "art-old",
	)
	require.NoError(t, err)

	insert := func() error {
		_, err := db.Exec(
			`INSERT INTO version_diff_results
			 (artifact_id, previous_artifact, diff_at, verdict, findings_json,
			  ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used)
			 VALUES (?, ?, datetime('now'), 'CLEAN', '[]', 'CLEAN', 0.9, 'gpt-5.4-mini', 'abc123', 1500)`,
			"art-new", "art-old",
		)
		return err
	}

	require.NoError(t, insert(), "first insert must succeed")
	require.Error(t, insert(), "second insert with identical AI key must fail unique constraint")
}
