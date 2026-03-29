-- Migration 006: Rescan scheduler indexes and bootstrap rescan_due_at.

-- Index for efficient rescan scheduler query: status + rescan_due_at.
CREATE INDEX IF NOT EXISTS idx_artifact_status_rescan
    ON artifact_status(status, rescan_due_at);

-- Index for ORDER BY last_accessed_at in priority query.
CREATE INDEX IF NOT EXISTS idx_artifacts_last_accessed
    ON artifacts(last_accessed_at);

-- Bootstrap rescan_due_at for existing CLEAN artifacts so the scheduler
-- picks them up. Sets rescan_due_at = cached_at + 24 hours.
UPDATE artifact_status
SET rescan_due_at = (
    SELECT cached_at + INTERVAL '24 hours'
    FROM artifacts
    WHERE artifacts.id = artifact_status.artifact_id
)
WHERE status = 'CLEAN' AND rescan_due_at IS NULL;
