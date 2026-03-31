package docker

import (
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// repoColumns is the explicit column list for docker_repositories queries.
// Keep in sync with the DockerRepository struct fields.
const repoColumns = "id, registry, name, is_internal, created_at, last_synced_at, sync_enabled"

// DockerRepository represents a row in docker_repositories.
type DockerRepository struct {
	ID           int64      `db:"id" json:"id"`
	Registry     string     `db:"registry" json:"registry"`
	Name         string     `db:"name" json:"name"`
	IsInternal   bool       `db:"is_internal" json:"is_internal"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	LastSyncedAt *time.Time `db:"last_synced_at" json:"last_synced_at,omitempty"`
	SyncEnabled  bool       `db:"sync_enabled" json:"sync_enabled"`
}

// EnsureRepository returns the existing repo or creates a new one.
// SECURITY: Uses atomic INSERT ... ON CONFLICT DO NOTHING + SELECT to avoid TOCTOU race conditions
// under concurrent first-access for the same image.
func EnsureRepository(db *config.GateDB, registry, name string, isInternal bool) (*DockerRepository, error) {
	now := time.Now().UTC()
	// Atomic: ON CONFLICT DO NOTHING avoids unique constraint violation under concurrent access.
	_, _ = db.Exec(
		`INSERT INTO docker_repositories (registry, name, is_internal, created_at, sync_enabled)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (registry, name) DO NOTHING`,
		registry, name, isInternal, now, !isInternal,
	)

	// Always SELECT — either we just inserted or the row already existed.
	var repo DockerRepository
	err := db.Get(&repo, "SELECT "+repoColumns+" FROM docker_repositories WHERE registry = ? AND name = ?", registry, name)
	if err != nil {
		return nil, fmt.Errorf("docker: querying repository: %w", err)
	}
	return &repo, nil
}

// GetRepositoryByID returns a single repository by its ID.
func GetRepositoryByID(db *config.GateDB, id int64) (*DockerRepository, error) {
	var repo DockerRepository
	err := db.Get(&repo, "SELECT "+repoColumns+" FROM docker_repositories WHERE id = ?", id)
	if err != nil {
		return nil, fmt.Errorf("docker: getting repository %d: %w", id, err)
	}
	return &repo, nil
}

// ListRepositories returns all repos, optionally filtered by registry.
func ListRepositories(db *config.GateDB, registry string) ([]DockerRepository, error) {
	var repos []DockerRepository
	if registry != "" {
		return repos, db.Select(&repos, "SELECT "+repoColumns+" FROM docker_repositories WHERE registry = ? ORDER BY name", registry)
	}
	return repos, db.Select(&repos, "SELECT "+repoColumns+" FROM docker_repositories ORDER BY registry, name")
}
