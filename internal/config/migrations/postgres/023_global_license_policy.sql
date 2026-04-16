CREATE TABLE IF NOT EXISTS global_license_policy (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    blocked_json   TEXT,
    warned_json    TEXT,
    allowed_json   TEXT,
    unknown_action TEXT,
    on_sbom_error  TEXT,
    or_semantics   TEXT,
    updated_at     TIMESTAMPTZ NOT NULL,
    updated_by     TEXT
);
