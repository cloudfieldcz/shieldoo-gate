CREATE TABLE IF NOT EXISTS policy_overrides (
    id         SERIAL PRIMARY KEY,
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    scope      TEXT NOT NULL DEFAULT 'version',
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'api',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_policy_overrides_lookup ON policy_overrides(ecosystem, name, version, revoked);
