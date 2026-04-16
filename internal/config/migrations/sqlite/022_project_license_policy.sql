-- Per-project license policy override. One row per project.
-- mode = 'inherit' (use global) | 'override' (use JSON fields) | 'disabled' (skip check)
-- NOTE: per-project overrides are only honored at runtime when projects.mode=strict
-- (see internal/license/evaluator.go). In lazy mode the global policy always applies.
CREATE TABLE IF NOT EXISTS project_license_policy (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    mode           TEXT NOT NULL DEFAULT 'inherit',
    blocked_json   TEXT,
    warned_json    TEXT,
    allowed_json   TEXT,
    unknown_action TEXT,
    updated_at     DATETIME NOT NULL,
    updated_by     TEXT
);
