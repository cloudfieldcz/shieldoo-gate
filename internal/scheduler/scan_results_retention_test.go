package scheduler

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestScanResultsRetention_DeletesOldRows_KeepsRecentAndCurrent(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// Seed an artifact (FK target).
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'pypi', 'foo', '1.0', '', '', 0, datetime('now'), datetime('now'), '')`,
		"art-1",
	)
	require.NoError(t, err)

	insert := func(daysAgo int) int64 {
		res, err := db.Exec(
			`INSERT INTO scan_results
			   (artifact_id, scanned_at, scanner_name, scanner_version, verdict, confidence, findings_json, duration_ms)
			 VALUES (?, datetime('now', ?), 'builtin-typosquat', '1.0.0', 'CLEAN', 1.0, '[]', 0)`,
			"art-1", "-"+strconv.Itoa(daysAgo)+" days",
		)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		return id
	}

	insert(120)         // ancient — should be deleted
	insert(95)          // ancient — should be deleted
	recentID := insert(30) // recent — keep
	currentID := insert(100) // ancient but referenced as last_scan_id — keep

	// Make currentID the "current" scan for the artifact.
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, last_scan_id) VALUES (?, 'CLEAN', ?)`,
		"art-1", currentID,
	)
	require.NoError(t, err)

	NewScanResultsRetentionScheduler(db).runOnce(context.Background())

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM scan_results"))
	assert.Equal(t, 2, n, "expected the two ancient un-referenced rows to be deleted")

	var ids []int64
	require.NoError(t, db.Select(&ids, "SELECT id FROM scan_results ORDER BY id"))
	assert.Contains(t, ids, recentID, "recent row must be retained")
	assert.Contains(t, ids, currentID, "row referenced by artifact_status.last_scan_id must be retained even when ancient")
}
