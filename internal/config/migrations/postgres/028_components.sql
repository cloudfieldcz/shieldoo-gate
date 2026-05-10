CREATE TABLE IF NOT EXISTS components (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT  NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    name            TEXT    NOT NULL,
    display_name    TEXT,
    description     TEXT,
    ecosystem       TEXT    NOT NULL,
    repo_url        TEXT,
    ai_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_via     TEXT    NOT NULL DEFAULT 'lazy',
    last_scan_id    BIGINT,
    UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_components_last_scan_id ON components(last_scan_id);
CREATE INDEX IF NOT EXISTS idx_components_project_enabled ON components(project_id, enabled);
