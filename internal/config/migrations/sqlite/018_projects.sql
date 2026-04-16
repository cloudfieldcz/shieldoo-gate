-- Projects registry: each Basic auth username (normalized, regex-validated) maps to a project.
-- Lazy mode: new labels create projects automatically (rate-limited, capped).
-- Strict mode: unknown labels are rejected at auth time.
CREATE TABLE IF NOT EXISTS projects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    label         TEXT NOT NULL,
    display_name  TEXT,
    description   TEXT,
    created_at    DATETIME NOT NULL,
    created_via   TEXT NOT NULL DEFAULT 'lazy',
    enabled       INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_label ON projects(label);

-- Seed the default project (used as fallback for empty Basic auth username).
INSERT OR IGNORE INTO projects (label, display_name, created_via, created_at)
VALUES ('default', 'Default Project', 'seed', CURRENT_TIMESTAMP);
