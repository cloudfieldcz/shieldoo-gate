-- Add project_id to audit_log. Nullable to preserve older rows.
-- MUST use ALTER TABLE ADD COLUMN only (audit_log is append-only — security invariant #5).
ALTER TABLE audit_log ADD COLUMN project_id INTEGER REFERENCES projects(id);

CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, ts);
