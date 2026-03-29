-- Add index for filtering audit_log by event_type (used by alert system per-channel filtering)
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type, ts);
