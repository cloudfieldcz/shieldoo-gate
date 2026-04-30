-- Migration 024 (SQLite): extend version_diff_results for AI-driven scanner.
-- SQLite cannot ALTER COLUMN DROP NOT NULL, so we recreate the table and copy.
-- Pattern matches migration 007. No explicit BEGIN/COMMIT — db.Exec processes
-- multi-statement bodies; SQLite handles each statement implicitly. PRAGMA
-- foreign_keys is left ON (the default); the FK target (artifacts.id) is not
-- changed by this migration so the rename succeeds without disabling it.
-- Dedup is implicit: ORDER BY id DESC + INSERT OR IGNORE keeps the first
-- (newest) row per legacy pair, dropping older duplicates.

CREATE TABLE IF NOT EXISTS version_diff_results_v24 (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id        TEXT NOT NULL,
    previous_artifact  TEXT NOT NULL REFERENCES artifacts(id),
    diff_at            DATETIME NOT NULL,
    files_added        INTEGER,
    files_removed      INTEGER,
    files_modified     INTEGER,
    size_ratio         REAL,
    max_entropy_delta  REAL,
    new_dependencies   TEXT,
    sensitive_changes  TEXT,
    verdict            TEXT NOT NULL,
    findings_json      TEXT NOT NULL,
    ai_verdict         TEXT,
    ai_confidence      REAL,
    ai_explanation     TEXT,
    ai_model_used      TEXT,
    ai_prompt_version  TEXT,
    ai_tokens_used     INTEGER,
    previous_version   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_version_diff_pair
    ON version_diff_results_v24(artifact_id, previous_artifact, ai_model_used, ai_prompt_version);

INSERT OR IGNORE INTO version_diff_results_v24
    (id, artifact_id, previous_artifact, diff_at,
     files_added, files_removed, files_modified, size_ratio, max_entropy_delta,
     new_dependencies, sensitive_changes, verdict, findings_json,
     ai_verdict, ai_confidence, ai_explanation, ai_model_used, ai_prompt_version, ai_tokens_used, previous_version)
    SELECT id, artifact_id, previous_artifact, diff_at,
           files_added, files_removed, files_modified, size_ratio, max_entropy_delta,
           new_dependencies, sensitive_changes, verdict, findings_json,
           NULL, NULL, NULL, NULL, NULL, NULL, NULL
      FROM version_diff_results
     ORDER BY id DESC;

DROP TABLE IF EXISTS version_diff_results;
ALTER TABLE version_diff_results_v24 RENAME TO version_diff_results;

CREATE INDEX IF NOT EXISTS idx_version_diff_artifact ON version_diff_results(artifact_id);
