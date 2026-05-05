-- Per-project, per-package policy overrides.
--
-- Adds two columns to policy_overrides (originally global, allow-only):
--   project_id  NULL = global (preserves existing typosquat overrides)
--               non-null = scoped to one project
--   kind        'allow' = whitelist (let through despite a block)
--               'deny'  = blacklist (block despite an allowance)
--
-- The unique-active index is rebuilt to include project_id and kind, so a
-- project may hold at most one active allow + one active deny per
-- (ecosystem, name, version, scope). COALESCE keeps NULL project_id rows
-- (global) distinct from project rows.
--
-- SQLite lacks `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we use the
-- table-recreation pattern (matches migration 007 / 024) to stay idempotent
-- under TestInitDB_Idempotent which re-runs every migration body on the
-- same DB.

CREATE TABLE IF NOT EXISTS policy_overrides_v26 (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    scope      TEXT NOT NULL DEFAULT 'version',
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT 'allow' CHECK (kind IN ('allow', 'deny')),
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'api',
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    revoked    INTEGER NOT NULL DEFAULT 0,
    revoked_at DATETIME
);

INSERT OR REPLACE INTO policy_overrides_v26
    (id, ecosystem, name, version, scope, reason, created_by, created_at, expires_at, revoked, revoked_at)
    SELECT id, ecosystem, name, version, scope, reason, created_by, created_at, expires_at, revoked, revoked_at
    FROM policy_overrides;

DROP TABLE IF EXISTS policy_overrides;
ALTER TABLE policy_overrides_v26 RENAME TO policy_overrides;

CREATE INDEX IF NOT EXISTS idx_policy_overrides_lookup
    ON policy_overrides(ecosystem, name, version, revoked);

CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_overrides_unique_active
    ON policy_overrides(ecosystem, name, version, scope, COALESCE(project_id, 0), kind)
    WHERE revoked = 0;

CREATE INDEX IF NOT EXISTS idx_policy_overrides_project_lookup
    ON policy_overrides(project_id, ecosystem, name, version, revoked);
