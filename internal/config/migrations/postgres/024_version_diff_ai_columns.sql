-- Migration 024: extend version_diff_results for AI-driven scanner.
-- Adds AI columns, relaxes NOT NULL on legacy heuristic metrics, dedupes existing
-- rows on (artifact_id, previous_artifact), and adds the idempotency UNIQUE INDEX.
-- No explicit BEGIN/COMMIT — the runner calls db.Exec per migration; multi-statement
-- bodies are processed by lib/pq's simple-query protocol. (See plan rationale.)

ALTER TABLE version_diff_results
    ADD COLUMN ai_verdict        TEXT,
    ADD COLUMN ai_confidence     REAL,
    ADD COLUMN ai_explanation    TEXT,
    ADD COLUMN ai_model_used     TEXT,
    ADD COLUMN ai_prompt_version TEXT,
    ADD COLUMN ai_tokens_used    INTEGER,
    ADD COLUMN previous_version  TEXT;

ALTER TABLE version_diff_results ALTER COLUMN size_ratio        DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN max_entropy_delta DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN files_added       DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN files_modified    DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN files_removed     DROP NOT NULL;

-- Deduplicate: keep the row with the largest id per (artifact_id, previous_artifact).
DELETE FROM version_diff_results
 WHERE id NOT IN (
   SELECT MAX(id) FROM version_diff_results
    GROUP BY artifact_id, previous_artifact
 );

-- Idempotency key. Uses the AI columns so a model or prompt change invalidates cache.
-- Note on NULL semantics: legacy v1.x rows have ai_model_used=NULL and ai_prompt_version=NULL.
-- SQL UNIQUE treats NULL as distinct, so the legacy row coexists with v2.0 rows that have
-- non-NULL values for both columns. New v2.0 rows ALWAYS persist non-NULL ai_model_used
-- (the model name) and non-empty ai_prompt_version (SHA[:12] of the bridge's system prompt
-- — see plan-6b lookupCache for how this is read back via DiffScanResponse.prompt_version).
CREATE UNIQUE INDEX IF NOT EXISTS uq_version_diff_pair
    ON version_diff_results(artifact_id, previous_artifact, ai_model_used, ai_prompt_version);
