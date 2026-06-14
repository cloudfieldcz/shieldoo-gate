-- Maps a pushed blob digest to the manifest (artifact) that references it, so blob
-- serving can be gated against the manifest's quarantine status with one indexed
-- lookup. Populated at manifest-allow time. Not an FK on artifact_id by the same
-- append-only reasoning as audit_log extensions.
CREATE TABLE IF NOT EXISTS docker_blob_refs (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id              INTEGER NOT NULL REFERENCES docker_repositories(id),
    blob_digest          TEXT NOT NULL,
    manifest_artifact_id TEXT NOT NULL,
    created_at           DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_docker_blob_refs_lookup ON docker_blob_refs(repo_id, blob_digest);
CREATE UNIQUE INDEX IF NOT EXISTS idx_docker_blob_refs_uniq ON docker_blob_refs(repo_id, blob_digest, manifest_artifact_id);
