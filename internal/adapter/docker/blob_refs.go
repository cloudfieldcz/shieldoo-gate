package docker

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// RecordBlobRefs records, idempotently, that manifestArtifactID references each of
// the given blob digests in repo repoID. Called at manifest-allow time.
func RecordBlobRefs(db *config.GateDB, repoID int64, manifestArtifactID string, digests []string) error {
	now := time.Now().UTC()
	for _, d := range digests {
		if d == "" {
			continue
		}
		if _, err := db.Exec(
			db.Rebind(`INSERT INTO docker_blob_refs (repo_id, blob_digest, manifest_artifact_id, created_at)
			           VALUES (?, ?, ?, ?)
			           ON CONFLICT (repo_id, blob_digest, manifest_artifact_id) DO NOTHING`),
			repoID, d, manifestArtifactID, now,
		); err != nil {
			return err
		}
	}
	return nil
}

// recordManifestBlobRefs parses the manifest body for config/layer/sub-manifest
// digests, appends the manifest's own digest, and records the references so layer
// serving can be gated by quarantine status. Non-fatal: a failure means serving
// falls back to deny for the unrecorded layers.
func (a *DockerAdapter) recordManifestBlobRefs(repoID int64, manifestArtifactID, manifestDigest string, body []byte) {
	refDigests := parseManifestBlobDigests(body)
	refDigests = append(refDigests, manifestDigest)
	if err := RecordBlobRefs(a.db, repoID, manifestArtifactID, refDigests); err != nil {
		log.Error().Err(err).Str("artifact", manifestArtifactID).Msg("docker push: failed to record blob refs")
	}
}

// BlobServable reports whether blobDigest is referenced by at least one
// NON-quarantined manifest in repoID. One indexed lookup + a bounded status check
// per referencing manifest (usually one). No object-store I/O, no manifest parsing.
func BlobServable(ctx context.Context, db *config.GateDB, repoID int64, blobDigest string) (bool, error) {
	var artifactIDs []string
	if err := db.SelectContext(ctx, &artifactIDs,
		db.Rebind(`SELECT manifest_artifact_id FROM docker_blob_refs WHERE repo_id = ? AND blob_digest = ?`),
		repoID, blobDigest,
	); err != nil {
		return false, err
	}
	for _, aid := range artifactIDs {
		status, err := adapter.GetArtifactStatus(db, aid)
		if err != nil {
			return false, err
		}
		if status == nil || status.Status != model.StatusQuarantined {
			return true, nil // referenced by a non-quarantined manifest
		}
	}
	return false, nil
}

// parseManifestBlobDigests extracts config + layer digests (single manifest) and
// sub-manifest digests (manifest list / image index). For a manifest list, each
// child manifest is pushed separately and records its OWN config/layer refs, so a
// child's layers are gated by that child's quarantine status.
func parseManifestBlobDigests(manifestBytes []byte) []string {
	var m struct {
		Config    struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil
	}
	var out []string
	if m.Config.Digest != "" {
		out = append(out, m.Config.Digest)
	}
	for _, l := range m.Layers {
		if l.Digest != "" {
			out = append(out, l.Digest)
		}
	}
	for _, sub := range m.Manifests {
		if sub.Digest != "" {
			out = append(out, sub.Digest)
		}
	}
	return out
}
