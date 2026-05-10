-- CVE ignores: per-Component suppression of (cve_id, package_name) pairs.
-- Per-package semantics: package_version is informational only (records what was visible
-- when the ignore was created) and is NOT part of the matching predicate.
--
-- ON DELETE RESTRICT on component_id (NOT CASCADE): ignore rows are audit evidence and
-- cannot be silently destroyed by a component delete. Hard-delete requires explicit
-- revocation of all ignores first.
--
-- The lifecycle columns revoked_at / revoked_by_email are MUTABLE — that is lifecycle
-- state, not audit evidence. The append-only audit trail for ignore lifecycle lives in
-- audit_log rows (see CLAUDE.md security invariant #5).
CREATE TABLE IF NOT EXISTS cve_ignores (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id             INTEGER NOT NULL REFERENCES components(id) ON DELETE RESTRICT,
    cve_id                   TEXT    NOT NULL,
    package_name             TEXT    NOT NULL,
    package_version          TEXT,
    reason                   TEXT    NOT NULL,
    -- 1 if user clicked "Use this draft" in the Ignore modal at least once before submit.
    -- Audit reviewers should read this as "AI-influenced ignore decision."
    ai_draft_accepted        INTEGER NOT NULL DEFAULT 0,
    expires_at               DATETIME,
    -- The run from which the ignore was applied (PIN target for the retention reaper).
    created_against_run_id   INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
    created_by_email         TEXT    NOT NULL,
    created_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at               DATETIME,
    revoked_by_email         TEXT
);

-- Unique active ignore per (component, cve, package) — duplicate Create returns 409.
CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_ignores_unique_active
    ON cve_ignores(component_id, cve_id, package_name)
    WHERE revoked_at IS NULL;
-- IgnoreExpiryWatcher hourly query.
CREATE INDEX IF NOT EXISTS idx_cve_ignores_expires
    ON cve_ignores(expires_at) WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
