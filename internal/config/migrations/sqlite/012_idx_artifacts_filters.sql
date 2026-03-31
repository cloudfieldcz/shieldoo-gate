-- Migration 012: Indexes for artifact list filtering and sorting.
CREATE INDEX IF NOT EXISTS idx_artifacts_name_version ON artifacts(name ASC, version ASC);
CREATE INDEX IF NOT EXISTS idx_artifact_status_status ON artifact_status(status);
