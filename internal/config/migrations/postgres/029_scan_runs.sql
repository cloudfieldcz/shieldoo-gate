CREATE TABLE IF NOT EXISTS scan_runs (
    id                    BIGSERIAL PRIMARY KEY,
    component_id          BIGINT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    trigger               TEXT NOT NULL CHECK (trigger IN ('upload', 'rescan', 'manual')),
    status                TEXT NOT NULL CHECK (status IN ('pending', 'running', 'done', 'failed')),
    sbom_blob_path        TEXT NOT NULL,
    sbom_size_bytes       BIGINT NOT NULL,
    sbom_format           TEXT NOT NULL DEFAULT 'cyclonedx-json',
    sbom_sha256           TEXT NOT NULL,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at           TIMESTAMPTZ,
    scanner_status        TEXT,
    critical_count        BIGINT NOT NULL DEFAULT 0,
    high_count            BIGINT NOT NULL DEFAULT 0,
    medium_count          BIGINT NOT NULL DEFAULT 0,
    low_count             BIGINT NOT NULL DEFAULT 0,
    new_critical_count    BIGINT NOT NULL DEFAULT 0,
    new_high_count        BIGINT NOT NULL DEFAULT 0,
    component_count       BIGINT NOT NULL DEFAULT 0,
    error_message         TEXT,
    integrity_violated    BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_component_id ON scan_runs(component_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_new_crit
    ON scan_runs(started_at, new_critical_count, new_high_count, component_id);
