CREATE TABLE IF NOT EXISTS scan_findings (
    id              BIGSERIAL PRIMARY KEY,
    scan_run_id     BIGINT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    component_id    BIGINT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    cve_id          TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cvss_score      DOUBLE PRECISION,
    fixed_version   TEXT,
    summary         TEXT,
    detected_by     TEXT NOT NULL,
    is_suppressed   BOOLEAN NOT NULL DEFAULT FALSE,
    suppressed_by   BIGINT
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_run_active
    ON scan_findings(scan_run_id, is_suppressed);
CREATE INDEX IF NOT EXISTS idx_scan_findings_age
    ON scan_findings(component_id, cve_id, package_name);
CREATE INDEX IF NOT EXISTS idx_scan_findings_cve
    ON scan_findings(cve_id, package_name);
