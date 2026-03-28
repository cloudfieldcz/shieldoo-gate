CREATE TABLE IF NOT EXISTS policy_overrides (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    scope      TEXT NOT NULL DEFAULT 'version',
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'api',
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    revoked    INTEGER NOT NULL DEFAULT 0,
    revoked_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_policy_overrides_lookup ON policy_overrides(ecosystem, name, version, revoked);
