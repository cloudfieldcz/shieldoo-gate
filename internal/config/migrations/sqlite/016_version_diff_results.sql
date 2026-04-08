CREATE TABLE IF NOT EXISTS version_diff_results (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id       TEXT NOT NULL,
    previous_artifact TEXT NOT NULL REFERENCES artifacts(id),
    diff_at           DATETIME NOT NULL,
    files_added       INTEGER NOT NULL,
    files_removed     INTEGER NOT NULL,
    files_modified    INTEGER NOT NULL,
    size_ratio        REAL NOT NULL,
    max_entropy_delta REAL NOT NULL,
    new_dependencies  TEXT,
    sensitive_changes TEXT,
    verdict           TEXT NOT NULL,
    findings_json     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_version_diff_artifact ON version_diff_results(artifact_id);

-- Composite index for efficient previous-version lookup (ORDER BY cached_at DESC).
-- Supplements existing idx_artifacts_ecosystem_name(ecosystem, name) from 001_init.sql.
CREATE INDEX IF NOT EXISTS idx_artifacts_eco_name_cached ON artifacts(ecosystem, name, cached_at DESC);
