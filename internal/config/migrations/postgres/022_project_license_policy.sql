CREATE TABLE IF NOT EXISTS project_license_policy (
    id             SERIAL PRIMARY KEY,
    project_id     INTEGER NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    mode           TEXT NOT NULL DEFAULT 'inherit',
    blocked_json   TEXT,
    warned_json    TEXT,
    allowed_json   TEXT,
    unknown_action TEXT,
    updated_at     TIMESTAMPTZ NOT NULL,
    updated_by     TEXT
);
