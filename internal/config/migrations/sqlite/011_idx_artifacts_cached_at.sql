-- Migration 011: Index for ORDER BY cached_at DESC in artifact listing.
CREATE INDEX IF NOT EXISTS idx_artifacts_cached_at ON artifacts(cached_at DESC);
