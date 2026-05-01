-- Migration 025: tag rows with the version of the version-diff scanner that
-- produced them. Old heuristic rows remain NULL; v2.0+ rows write '2.0.0'.
-- Also adds a (verdict, diff_at) index used by the retention DELETE query.
ALTER TABLE version_diff_results
    ADD COLUMN scanner_version TEXT;

CREATE INDEX IF NOT EXISTS idx_version_diff_scanner_version
    ON version_diff_results(scanner_version);

-- Used by VersionDiffRetentionScheduler.runOnce:
-- DELETE WHERE verdict='CLEAN' AND diff_at < ?
CREATE INDEX IF NOT EXISTS idx_version_diff_verdict_diff_at
    ON version_diff_results(verdict, diff_at);
