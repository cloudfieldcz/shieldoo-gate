ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS component_id BIGINT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS scan_run_id  BIGINT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS ignore_id    BIGINT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS api_key_id   BIGINT;

CREATE INDEX IF NOT EXISTS idx_audit_log_component  ON audit_log(component_id, ts) WHERE component_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_scan_run   ON audit_log(scan_run_id) WHERE scan_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_ignore     ON audit_log(ignore_id)   WHERE ignore_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_log_api_key    ON audit_log(api_key_id)  WHERE api_key_id IS NOT NULL;
