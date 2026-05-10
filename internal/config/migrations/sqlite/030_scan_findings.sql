-- Scan findings: one row per (scan_run, CVE, package, version). component_id is denormalized
-- to allow Age-column derivation ("earliest run that contained this finding for this component")
-- without joining scan_runs per row.
CREATE TABLE IF NOT EXISTS scan_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    component_id    INTEGER NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    cve_id          TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    cvss_score      REAL,
    fixed_version   TEXT,
    -- Attacker-influenceable; UI must render as text only (no HTML).
    summary         TEXT,
    -- JSON array, e.g. ["osv","trivy"].
    detected_by     TEXT NOT NULL,
    is_suppressed   INTEGER NOT NULL DEFAULT 0,
    -- suppressed_by points to cve_ignores(id); FK is intentionally NOT declared here
    -- to keep migration ordering simple (cve_ignores is created in migration 031).
    -- The application (IgnoreService.ClearSuppression) sets this to NULL on Revoke;
    -- cve_ignores rows are never hard-deleted (lifecycle is revoked_at, not DELETE).
    suppressed_by   INTEGER
);

-- Per-run findings list. (scan_run_id, is_suppressed) lets Active and Ignored tab queries
-- on Screen 2 use index-only filtering instead of a post-scan filter.
CREATE INDEX IF NOT EXISTS idx_scan_findings_run_active
    ON scan_findings(scan_run_id, is_suppressed);
-- Age-column derivation.
CREATE INDEX IF NOT EXISTS idx_scan_findings_age
    ON scan_findings(component_id, cve_id, package_name);
-- Forensic queries ("find this CVE across the org").
CREATE INDEX IF NOT EXISTS idx_scan_findings_cve
    ON scan_findings(cve_id, package_name);
