-- Add user_email column to audit_log for tracking who performed admin actions.
-- Use table recreation pattern for idempotency (SQLite lacks ALTER TABLE ADD COLUMN IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS audit_log_v7 (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            DATETIME NOT NULL,
    event_type    TEXT NOT NULL,
    artifact_id   TEXT,
    client_ip     TEXT,
    user_agent    TEXT,
    reason        TEXT,
    metadata_json TEXT,
    user_email    TEXT DEFAULT ''
);

INSERT OR REPLACE INTO audit_log_v7 (id, ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json)
    SELECT id, ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json
    FROM audit_log;

DROP TABLE IF EXISTS audit_log;
ALTER TABLE audit_log_v7 RENAME TO audit_log;

CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type, ts);
