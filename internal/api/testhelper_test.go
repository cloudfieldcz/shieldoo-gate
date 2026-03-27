package api_test

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// newTestServer creates an in-memory SQLite-backed Server for use in tests.
func newTestServer(t *testing.T) (*api.Server, *sqlx.DB) {
	t.Helper()

	db, err := config.InitDB(":memory:")
	require.NoError(t, err, "failed to init in-memory database")
	t.Cleanup(func() { db.Close() })

	srv := api.NewServer(db, nil, nil, nil)
	return srv, db
}

// insertTestArtifact inserts a minimal artifact row and returns its id.
func insertTestArtifact(t *testing.T, db *sqlx.DB, id, ecosystem, name, version string) {
	t.Helper()

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, 'https://example.com', 'abc123', 1024, ?, ?, '/cache/test')`,
		id, ecosystem, name, version, now, now,
	)
	require.NoError(t, err, "failed to insert test artifact")
}
