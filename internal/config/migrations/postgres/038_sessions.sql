-- Server-side admin UI sessions. The session cookie now carries an opaque random
-- ID (not the raw OIDC ID token), so logout/expiry are enforced server-side and a
-- captured cookie can be revoked. See ADR-011.
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT        PRIMARY KEY,
    subject      TEXT        NOT NULL DEFAULT '',
    email        TEXT        NOT NULL DEFAULT '',
    name         TEXT        NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
