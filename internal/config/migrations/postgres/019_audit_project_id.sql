ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS project_id INTEGER REFERENCES projects(id);

CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, ts);
