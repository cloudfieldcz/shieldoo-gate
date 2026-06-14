-- See sqlite/037 for rationale. repo_id mirrors docker_repositories.id (SERIAL,
-- i.e. INTEGER) so the FK types match exactly. Not an FK on manifest_artifact_id by
-- the same append-only reasoning as audit_log extensions.
CREATE TABLE IF NOT EXISTS docker_blob_refs (
    id                   SERIAL PRIMARY KEY,
    repo_id              INTEGER NOT NULL REFERENCES docker_repositories(id),
    blob_digest          TEXT NOT NULL,
    manifest_artifact_id TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_docker_blob_refs_lookup ON docker_blob_refs(repo_id, blob_digest);
CREATE UNIQUE INDEX IF NOT EXISTS idx_docker_blob_refs_uniq ON docker_blob_refs(repo_id, blob_digest, manifest_artifact_id);
