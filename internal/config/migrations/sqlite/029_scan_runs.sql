-- Scan runs: one row per scan attempt (upload, scheduled rescan, manual rescan).
-- Denormalized severity counts (after suppression) and delta-vs-previous columns
-- are persisted here so list queries (Screen 1, badge endpoint) stay on a single
-- index scan and don't need correlated subqueries against scan_findings.
CREATE TABLE IF NOT EXISTS scan_runs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id          INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    trigger               TEXT NOT NULL CHECK (trigger IN ('upload', 'rescan', 'manual')),
    status                TEXT NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed')),
    sbom_blob_path        TEXT NOT NULL,
    sbom_size_bytes       INTEGER NOT NULL,
    sbom_format           TEXT NOT NULL DEFAULT 'cyclonedx-json',
    -- SHA-256 of canonical body for tamper detection on download.
    sbom_sha256           TEXT NOT NULL,
    started_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at           DATETIME,
    -- JSON: {"osv":"ok","trivy":"timeout"} — per-scanner status.
    scanner_status        TEXT,
    -- Denormalized severity counts after suppression. Persisted by Aggregator.
    critical_count        INTEGER NOT NULL DEFAULT 0,
    high_count            INTEGER NOT NULL DEFAULT 0,
    medium_count          INTEGER NOT NULL DEFAULT 0,
    low_count             INTEGER NOT NULL DEFAULT 0,
    -- Delta vs previous successful run for the same component. Persisted by DeltaEvaluator.
    new_critical_count    INTEGER NOT NULL DEFAULT 0,
    new_high_count        INTEGER NOT NULL DEFAULT 0,
    component_count       INTEGER NOT NULL DEFAULT 0,
    error_message         TEXT,
    -- Set to 1 by SBOM download handler when blob SHA-256 mismatches sbom_sha256.
    -- Subsequent downloads fast-fail with 502 until operator action. Never decremented.
    integrity_violated    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_component_id ON scan_runs(component_id, started_at DESC);
-- Covering index for /vulnerabilities/badge AND Screen 1 list filter ?has_new=true.
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_new_crit
    ON scan_runs(started_at, new_critical_count, new_high_count, component_id);
