-- triage_cache: stores AI triage decisions for balanced mode caching
CREATE TABLE IF NOT EXISTS triage_cache (
    cache_key    TEXT PRIMARY KEY,
    ecosystem    TEXT NOT NULL,
    name         TEXT NOT NULL,
    version      TEXT NOT NULL,
    decision     TEXT NOT NULL,
    confidence   REAL NOT NULL,
    explanation  TEXT NOT NULL,
    model_used   TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    expires_at   TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_triage_cache_expires ON triage_cache(expires_at);

-- Additional index for audit_log queries on artifact + event type
CREATE INDEX IF NOT EXISTS idx_audit_log_artifact_event ON audit_log(artifact_id, event_type);
