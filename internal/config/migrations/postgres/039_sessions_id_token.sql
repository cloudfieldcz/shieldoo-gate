-- Store the raw OIDC id_token on the session so logout can pass it as id_token_hint
-- for RP-initiated logout (OIDC end-session). NOT NULL DEFAULT '' matches the existing
-- sessions columns; existing rows get '' and degrade to local-only logout. The default MUST
-- stay a constant literal ('') so PostgreSQL 11+ keeps this metadata-only (a volatile/
-- expression default would force a full table rewrite). IF NOT EXISTS keeps it idempotent.
-- See #31 / ADR-016.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS id_token TEXT NOT NULL DEFAULT '';
