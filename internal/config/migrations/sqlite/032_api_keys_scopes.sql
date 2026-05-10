-- Add the `scopes` column to api_keys for least-privilege PAT enforcement.
-- Backfill: existing rows get EXACTLY the capability they have today, which is
-- proxy:fetch only. The admin API has been OIDC-only since launch, so no existing
-- PAT can authenticate against admin endpoints today. Backfilling broader scopes
-- would grant new privileges that didn't exist before.
--
-- Use table recreation pattern for idempotency (SQLite lacks ALTER TABLE ADD COLUMN
-- IF NOT EXISTS); mirrors the pattern used in 007_audit_user_email.sql.
CREATE TABLE IF NOT EXISTS api_keys_v32 (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash     TEXT     NOT NULL UNIQUE,
    name         TEXT     NOT NULL,
    owner_email  TEXT     NOT NULL DEFAULT '',
    enabled      INTEGER  NOT NULL DEFAULT 1,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    expires_at   DATETIME,
    scopes       TEXT     NOT NULL DEFAULT ''
);

INSERT OR REPLACE INTO api_keys_v32 (id, key_hash, name, owner_email, enabled, created_at, last_used_at, expires_at, scopes)
    SELECT id, key_hash, name, owner_email, enabled, created_at, last_used_at, expires_at, 'proxy:fetch'
    FROM api_keys;

DROP TABLE IF EXISTS api_keys;
ALTER TABLE api_keys_v32 RENAME TO api_keys;

-- Recreate indexes that lived on api_keys.
CREATE INDEX IF NOT EXISTS idx_api_keys_owner_email ON api_keys(owner_email);
