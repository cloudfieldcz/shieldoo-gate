-- Docker tags table: maps tag names to manifest digests for pushed images.
CREATE TABLE IF NOT EXISTS docker_tags (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id         INTEGER NOT NULL REFERENCES docker_repositories(id),
    tag             TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    artifact_id     TEXT REFERENCES artifacts(id),
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_docker_tags_repo_tag ON docker_tags(repo_id, tag);
CREATE INDEX IF NOT EXISTS idx_docker_tags_digest ON docker_tags(manifest_digest);
