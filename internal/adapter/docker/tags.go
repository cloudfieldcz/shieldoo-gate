package docker

import (
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// DockerTag represents a row in the docker_tags table.
type DockerTag struct {
	ID             int64     `db:"id" json:"id"`
	RepoID         int64     `db:"repo_id" json:"repo_id"`
	Tag            string    `db:"tag" json:"tag"`
	ManifestDigest string    `db:"manifest_digest" json:"manifest_digest"`
	ArtifactID     *string   `db:"artifact_id" json:"artifact_id"`
	CreatedAt      time.Time `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time `db:"updated_at" json:"updated_at"`
}

// UpsertTag creates or updates a tag for a repository.
// Uses INSERT ... ON CONFLICT DO UPDATE on the unique (repo_id, tag) constraint.
// An empty artifactID is stored as NULL to satisfy the FK constraint.
func UpsertTag(db *config.GateDB, repoID int64, tag, manifestDigest, artifactID string) error {
	now := time.Now().UTC()
	// Store empty artifact_id as NULL to avoid FK constraint violations.
	var artID interface{} = artifactID
	if artifactID == "" {
		artID = nil
	}
	_, err := db.Exec(
		`INSERT INTO docker_tags (repo_id, tag, manifest_digest, artifact_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(repo_id, tag) DO UPDATE SET
		     manifest_digest = excluded.manifest_digest,
		     artifact_id = excluded.artifact_id,
		     updated_at = excluded.updated_at`,
		repoID, tag, manifestDigest, artID, now, now,
	)
	if err != nil {
		return fmt.Errorf("docker: upserting tag %s: %w", tag, err)
	}
	return nil
}

// ListTags returns all tags for a given repository.
func ListTags(db *config.GateDB, repoID int64) ([]DockerTag, error) {
	var tags []DockerTag
	err := db.Select(&tags,
		"SELECT * FROM docker_tags WHERE repo_id = ? ORDER BY tag", repoID)
	if err != nil {
		return nil, fmt.Errorf("docker: listing tags for repo %d: %w", repoID, err)
	}
	return tags, nil
}

// DeleteTag removes a tag from a repository.
func DeleteTag(db *config.GateDB, repoID int64, tag string) error {
	result, err := db.Exec(
		"DELETE FROM docker_tags WHERE repo_id = ? AND tag = ?", repoID, tag)
	if err != nil {
		return fmt.Errorf("docker: deleting tag %s: %w", tag, err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("docker: tag %s not found", tag)
	}
	return nil
}

// GetTagByDigest returns tags matching a specific manifest digest for a repository.
func GetTagByDigest(db *config.GateDB, repoID int64, manifestDigest string) ([]DockerTag, error) {
	var tags []DockerTag
	err := db.Select(&tags,
		"SELECT * FROM docker_tags WHERE repo_id = ? AND manifest_digest = ? ORDER BY tag",
		repoID, manifestDigest)
	if err != nil {
		return nil, fmt.Errorf("docker: getting tags by digest %s: %w", manifestDigest, err)
	}
	return tags, nil
}
