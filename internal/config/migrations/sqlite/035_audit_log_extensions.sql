-- Extend audit_log with nullable foreign-key-shaped columns for vuln-scan lifecycle events.
--
-- DELIBERATE DEVIATION FROM EXISTING CONVENTION (migration 019 used a real FK):
-- We DROP the FK on these four columns. audit_log is the append-only forensic record
-- per CLAUDE.md security invariant #5; it must survive the deletion of any referenced
-- row in components / scan_runs / cve_ignores / api_keys.
--
-- Use table recreation pattern for idempotency (SQLite lacks ALTER TABLE ADD COLUMN
-- IF NOT EXISTS); mirrors 007_audit_user_email.sql.
CREATE TABLE IF NOT EXISTS audit_log_v35 (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            DATETIME NOT NULL,
    event_type    TEXT NOT NULL,
    artifact_id   TEXT,
    client_ip     TEXT,
    user_agent    TEXT,
    reason        TEXT,
    metadata_json TEXT,
    user_email    TEXT DEFAULT '',
    project_id    INTEGER,
    component_id  INTEGER,
    scan_run_id   INTEGER,
    ignore_id     INTEGER,
    api_key_id    INTEGER
);

INSERT OR REPLACE INTO audit_log_v35
    (id, ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json,
     user_email, project_id, component_id, scan_run_id, ignore_id, api_key_id)
    SELECT id, ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json,
           user_email, project_id, NULL, NULL, NULL, NULL
    FROM audit_log;

DROP TABLE IF EXISTS audit_log;
ALTER TABLE audit_log_v35 RENAME TO audit_log;

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_component  ON audit_log(component_id, ts) WHERE component_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_scan_run   ON audit_log(scan_run_id) WHERE scan_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_ignore     ON audit_log(ignore_id)   WHERE ignore_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_api_key    ON audit_log(api_key_id)  WHERE api_key_id IS NOT NULL;
