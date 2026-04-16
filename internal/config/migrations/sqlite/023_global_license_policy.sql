-- Runtime-mutable global license policy. Singleton row (id = 1).
-- When present, overrides the policy.licenses.* YAML config.
-- When absent or empty, the YAML config is effective.
--
-- on_sbom_error controls behavior when no SBOM data is available for an
-- artifact: "allow" | "warn" | "block".
CREATE TABLE IF NOT EXISTS global_license_policy (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    enabled        INTEGER NOT NULL DEFAULT 1,
    blocked_json   TEXT,
    warned_json    TEXT,
    allowed_json   TEXT,
    unknown_action TEXT,
    on_sbom_error  TEXT,
    or_semantics   TEXT,
    updated_at     DATETIME NOT NULL,
    updated_by     TEXT
);
