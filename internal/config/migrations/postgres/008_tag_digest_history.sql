-- Tag digest history: tracks all observed digests for each ecosystem/name/version tuple.
-- Used by tag mutability detection to identify upstream content changes.

CREATE TABLE IF NOT EXISTS tag_digest_history (
    id              SERIAL PRIMARY KEY,
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    tag_or_version  TEXT NOT NULL,
    digest          TEXT NOT NULL,
    first_seen_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ecosystem, name, tag_or_version, digest)
);

CREATE INDEX IF NOT EXISTS idx_tag_digest_history_lookup
    ON tag_digest_history(ecosystem, name, tag_or_version);
