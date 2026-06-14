package docker_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

func newBlobRefsTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// mustQuarantine inserts the manifest artifact (artifact_status FKs to artifacts)
// and a QUARANTINED status row for it.
func mustQuarantine(t *testing.T, db *config.GateDB, artifactID string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'docker', 'internal/app', '1.0', '', '', 0, ?, ?, '')`,
		artifactID, now, now,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, rescan_due_at)
		 VALUES (?, ?, ?, ?, ?)`,
		artifactID, string(model.StatusQuarantined), "malware", now, now.Add(168*time.Hour),
	)
	require.NoError(t, err)
}

func TestBlobRefs_RecordAndCheck(t *testing.T) {
	db := newBlobRefsTestDB(t)
	repo, err := docker.EnsureRepository(db, "", "internal/app", true)
	require.NoError(t, err)
	repoID := repo.ID

	refs := []string{"sha256:layer1", "sha256:layer2", "sha256:manifestdig"}
	if err := docker.RecordBlobRefs(db, repoID, "docker:internal_app:1.0", refs); err != nil {
		t.Fatalf("RecordBlobRefs: %v", err)
	}
	// Idempotent re-record.
	if err := docker.RecordBlobRefs(db, repoID, "docker:internal_app:1.0", refs); err != nil {
		t.Fatalf("RecordBlobRefs (re-run): %v", err)
	}

	// Clean manifest → layer servable.
	ok, err := docker.BlobServable(context.Background(), db, repoID, "sha256:layer1")
	if err != nil || !ok {
		t.Fatalf("BlobServable clean = %v, %v; want true", ok, err)
	}
	// Unknown blob → not servable.
	ok, _ = docker.BlobServable(context.Background(), db, repoID, "sha256:nope")
	if ok {
		t.Fatal("unknown blob must not be servable")
	}
	// Quarantine the manifest → its layers no longer servable.
	mustQuarantine(t, db, "docker:internal_app:1.0")
	ok, _ = docker.BlobServable(context.Background(), db, repoID, "sha256:layer1")
	if ok {
		t.Fatal("layer of quarantined manifest must not be servable")
	}
}
