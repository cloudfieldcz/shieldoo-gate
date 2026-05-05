-- Per-project, per-package policy overrides. See sqlite migration 026 for design notes.
ALTER TABLE policy_overrides ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE policy_overrides ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'allow' CHECK (kind IN ('allow', 'deny'));

DROP INDEX IF EXISTS idx_policy_overrides_unique_active;
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_overrides_unique_active
    ON policy_overrides(ecosystem, name, version, scope, COALESCE(project_id, 0), kind)
    WHERE revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_policy_overrides_project_lookup
    ON policy_overrides(project_id, ecosystem, name, version, revoked);
