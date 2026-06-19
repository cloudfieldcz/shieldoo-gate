-- Store the raw OIDC id_token on the session so logout can pass it as id_token_hint
-- for RP-initiated logout (OIDC end-session). NOT NULL DEFAULT '' matches the existing
-- sessions columns; existing rows get '' and degrade to local-only logout. See #31 / ADR-016.
--
-- SQLite lacks `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we use the table-recreation
-- pattern (matches migrations 007 / 026) to stay idempotent under TestInitDB_Idempotent,
-- which re-runs every migration body on the same DB.

CREATE TABLE IF NOT EXISTS sessions_v39 (
    id           TEXT     PRIMARY KEY,
    subject      TEXT     NOT NULL DEFAULT '',
    email        TEXT     NOT NULL DEFAULT '',
    name         TEXT     NOT NULL DEFAULT '',
    id_token     TEXT     NOT NULL DEFAULT '',
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME NOT NULL
);

INSERT OR REPLACE INTO sessions_v39 (id, subject, email, name, created_at, last_seen_at, expires_at)
    SELECT id, subject, email, name, created_at, last_seen_at, expires_at
    FROM sessions;

DROP TABLE IF EXISTS sessions;
ALTER TABLE sessions_v39 RENAME TO sessions;

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
