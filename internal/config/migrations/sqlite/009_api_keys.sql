CREATE TABLE IF NOT EXISTS api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash     TEXT     NOT NULL UNIQUE,
    name         TEXT     NOT NULL,
    owner_email  TEXT     NOT NULL DEFAULT '',
    enabled      INTEGER  NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    expires_at   DATETIME
);
