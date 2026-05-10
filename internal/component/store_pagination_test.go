package component_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// seed returns the inserted run IDs in INSERT order (ascending). The store
// orders DESC so the first page returns these in reverse. `name` must be
// unique per project — pass a distinct name when seeding multiple
// components in the same test.
func seedScanRuns(t *testing.T, db *config.GateDB, name string, n int) (componentID int64, runIDs []int64) {
	t.Helper()
	res, err := db.Exec(`INSERT INTO components (project_id, name, ecosystem, enabled)
	                     VALUES (1, ?, 'pypi', 1)`, name)
	require.NoError(t, err)
	componentID, err = res.LastInsertId()
	require.NoError(t, err)
	for i := 0; i < n; i++ {
		path := "sboms/components/" + strconv.FormatInt(componentID, 10) + "/run-" + strconv.Itoa(i) + ".json"
		r, err := db.Exec(
			`INSERT INTO scan_runs
			   (component_id, trigger, status, sbom_blob_path, sbom_size_bytes, sbom_format, sbom_sha256,
			    started_at, finished_at, scanner_status, critical_count, high_count, medium_count, low_count,
			    new_critical_count, new_high_count, component_count)
			 VALUES (?, 'upload', 'done', ?, 0, 'cyclonedx-json', '',
			         datetime('now'), datetime('now'), 'ok', 0, 0, 0, 0, 0, 0, 0)`,
			componentID, path,
		)
		require.NoError(t, err)
		id, err := r.LastInsertId()
		require.NoError(t, err)
		runIDs = append(runIDs, id)
	}
	return
}

func TestListScanRunsByComponent_FirstPageReturnsLatestN(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	componentID, runIDs := seedScanRuns(t, db, "cmp-a", 5)
	store := component.NewStore(db)

	got, err := store.ListScanRunsByComponent(context.Background(), componentID, 0, 3)
	require.NoError(t, err)
	require.Len(t, got, 3)
	// Ordered DESC by id: should be the last 3 inserted, reversed.
	assert.Equal(t, runIDs[4], got[0].ID)
	assert.Equal(t, runIDs[3], got[1].ID)
	assert.Equal(t, runIDs[2], got[2].ID)
}

func TestListScanRunsByComponent_CursorReturnsNextPage(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	componentID, runIDs := seedScanRuns(t, db, "cmp-a", 5)
	store := component.NewStore(db)

	page1, err := store.ListScanRunsByComponent(context.Background(), componentID, 0, 2)
	require.NoError(t, err)
	require.Len(t, page1, 2)

	// Cursor = id of last row on page 1. Page 2 should return rows whose id < cursor.
	cursor := page1[len(page1)-1].ID
	page2, err := store.ListScanRunsByComponent(context.Background(), componentID, cursor, 2)
	require.NoError(t, err)
	require.Len(t, page2, 2)
	assert.Equal(t, runIDs[2], page2[0].ID, "first row of page 2 must be the next id below the cursor")
	assert.Equal(t, runIDs[1], page2[1].ID)

	// Page 3 should yield the final remaining row.
	cursor = page2[len(page2)-1].ID
	page3, err := store.ListScanRunsByComponent(context.Background(), componentID, cursor, 2)
	require.NoError(t, err)
	require.Len(t, page3, 1)
	assert.Equal(t, runIDs[0], page3[0].ID)

	// Page 4 (cursor past the bottom) is empty — caller learns "no next page".
	cursor = page3[len(page3)-1].ID
	page4, err := store.ListScanRunsByComponent(context.Background(), componentID, cursor, 2)
	require.NoError(t, err)
	assert.Empty(t, page4)
}

// Cursor pages must not bleed across components.
func TestListScanRunsByComponent_CursorScopedPerComponent(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	componentA, runsA := seedScanRuns(t, db, "cmp-a", 3)
	_, _ = seedScanRuns(t, db, "cmp-b", 3) // componentB seeded; intentionally unused.

	store := component.NewStore(db)
	got, err := store.ListScanRunsByComponent(context.Background(), componentA, 0, 10)
	require.NoError(t, err)
	require.Len(t, got, 3)
	for _, run := range got {
		assert.Contains(t, runsA, run.ID, "component A page must contain only A's runs")
	}
}
