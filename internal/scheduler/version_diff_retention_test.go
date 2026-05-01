package scheduler

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestVersionDiffRetention_DeletesOldClean_KeepsSuspiciousAndRecent(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// Seed minimal artifacts to satisfy FK on version_diff_results.
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'pypi', 'foo', '1.0', '', '', 0, datetime('now'), datetime('now'), '')`,
		"art-new",
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'pypi', 'foo', '0.9', '', '', 0, datetime('now', '-200 days'), datetime('now', '-200 days'), '')`,
		"art-old",
	)
	require.NoError(t, err)

	// 1 row CLEAN + ancient (deletes), 1 SUSPICIOUS + ancient (kept), 1 CLEAN + recent (kept).
	insert := func(verdict string, daysAgo int) {
		_, err := db.Exec(
			`INSERT INTO version_diff_results
			 (artifact_id, previous_artifact, diff_at, verdict, findings_json,
			  ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used)
			 VALUES (?, ?, datetime('now', ?), ?, '[]', ?, 0.5, 'gpt-5.4-mini', ?, 100)`,
			"art-new", "art-old", "-"+strconv.Itoa(daysAgo)+" days", verdict, verdict,
			"p"+strconv.Itoa(daysAgo),
		)
		require.NoError(t, err)
	}
	insert("CLEAN", 100)      // ancient CLEAN — should be deleted
	insert("SUSPICIOUS", 200) // ancient SUSPICIOUS — keep
	insert("CLEAN", 30)       // recent CLEAN — keep

	NewVersionDiffRetentionScheduler(db).runOnce(context.Background())

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM version_diff_results"))
	require.Equal(t, 2, n, "expected one CLEAN deletion")

	var verdicts []string
	require.NoError(t, db.Select(&verdicts, "SELECT verdict FROM version_diff_results ORDER BY verdict"))
	require.Equal(t, []string{"CLEAN", "SUSPICIOUS"}, verdicts)
}
