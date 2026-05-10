-- Components: technology components belonging to a Project that get vulnerability-scanned
-- via CycloneDX SBOM uploads from CI. Each Component has a stable name (CI-supplied),
-- an ecosystem, and an optional repo_url that the AI Drafter can use after passing the
-- SSRF allowlist (see scanner-bridge/ssrf_guard.py).
--
-- ON DELETE RESTRICT on project_id (NOT CASCADE): a project cannot be hard-deleted while
-- it owns components. This protects ignore audit evidence — a project-level cascade would
-- transitively wipe every cve_ignores row and audit_log reference. The supported retirement
-- path is Project.Disable() (soft-disable).
CREATE TABLE IF NOT EXISTS components (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    -- Component name is regex-validated at write time:
    --   ^[a-z0-9][a-z0-9._/-]{0,255}$
    -- Reject NUL, control chars, RTL overrides, leading separators.
    name            TEXT    NOT NULL,
    display_name    TEXT,
    description     TEXT,
    ecosystem       TEXT    NOT NULL,
    -- Free-text URL; the AI Drafter applies a hardened SSRF allowlist before
    -- fetching from it. Storage of the URL is not gated by the allowlist.
    repo_url        TEXT,
    -- Per-component AI opt-out. Default true. When false, IgnoreReasonDrafter and
    -- any per-component AI service skips this Component even if the global
    -- ai_features.enabled flag is true.
    ai_enabled      INTEGER NOT NULL DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_via     TEXT    NOT NULL DEFAULT 'lazy',
    -- Pointer to most recent successful ScanRun. Maintained by ScanService.Run on commit.
    -- Used as a back-pointer to eliminate MAX(id) correlated subqueries on hot list path.
    last_scan_id    INTEGER,
    UNIQUE (project_id, name)
);

CREATE INDEX IF NOT EXISTS idx_components_last_scan_id ON components(last_scan_id);
-- Powers project-scoped list AND ManifestRescanScheduler population query.
CREATE INDEX IF NOT EXISTS idx_components_project_enabled ON components(project_id, enabled);
