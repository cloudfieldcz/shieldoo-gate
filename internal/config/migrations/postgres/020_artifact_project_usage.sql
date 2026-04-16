CREATE TABLE IF NOT EXISTS artifact_project_usage (
    artifact_id    TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    first_used_at  TIMESTAMPTZ NOT NULL,
    last_used_at   TIMESTAMPTZ NOT NULL,
    use_count      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (artifact_id, project_id)
);

CREATE INDEX IF NOT EXISTS idx_apu_project_last_used
    ON artifact_project_usage(project_id, last_used_at DESC);
