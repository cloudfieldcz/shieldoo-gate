CREATE TABLE IF NOT EXISTS projects (
    id            SERIAL PRIMARY KEY,
    label         TEXT NOT NULL,
    display_name  TEXT,
    description   TEXT,
    created_at    TIMESTAMPTZ NOT NULL,
    created_via   TEXT NOT NULL DEFAULT 'lazy',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_label ON projects(label);

INSERT INTO projects (label, display_name, created_via, created_at)
VALUES ('default', 'Default Project', 'seed', CURRENT_TIMESTAMP)
ON CONFLICT DO NOTHING;
