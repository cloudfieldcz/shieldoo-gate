CREATE TABLE IF NOT EXISTS cve_ignores (
    id                       BIGSERIAL PRIMARY KEY,
    component_id             BIGINT  NOT NULL REFERENCES components(id) ON DELETE RESTRICT,
    cve_id                   TEXT    NOT NULL,
    package_name             TEXT    NOT NULL,
    package_version          TEXT,
    reason                   TEXT    NOT NULL,
    ai_draft_accepted        BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at               TIMESTAMPTZ,
    created_against_run_id   BIGINT  REFERENCES scan_runs(id) ON DELETE SET NULL,
    created_by_email         TEXT    NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at               TIMESTAMPTZ,
    revoked_by_email         TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_ignores_unique_active
    ON cve_ignores(component_id, cve_id, package_name)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_cve_ignores_expires
    ON cve_ignores(expires_at) WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
