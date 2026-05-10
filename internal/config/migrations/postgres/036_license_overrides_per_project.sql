-- 036_license_overrides_per_project.sql (postgres)
-- Postgres twin of the SQLite migration. See SQLite file for design notes.
-- Differences: BOOLEAN literals (FALSE) instead of INTEGER 0/1.
--
-- Backfills currently-active global 'manual release' overrides into per-project
-- rows so operators see per-project visibility + isolated revoke. Globals stay
-- (revoked=FALSE) for compatibility; new license-block releases go straight to
-- per-project via the API.
--
-- Idempotent: NOT EXISTS guard prevents duplicates on re-run; ON CONFLICT
-- DO NOTHING covers concurrent inserts racing the unique partial index
-- idx_policy_overrides_unique_active.

INSERT INTO policy_overrides
    (ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, expires_at, revoked)
SELECT
    po.ecosystem, po.name, po.version, po.scope,
    p.id AS project_id,
    'allow' AS kind,
    'migrated 036: was global manual release; now per-project' AS reason,
    'migration:036' AS created_by,
    po.created_at,
    po.expires_at,
    FALSE AS revoked
FROM policy_overrides po
CROSS JOIN projects p
WHERE po.project_id IS NULL
  AND po.revoked = FALSE
  AND po.reason = 'manual release'
  AND NOT EXISTS (
      SELECT 1 FROM policy_overrides po2
      WHERE po2.project_id = p.id
        AND po2.ecosystem  = po.ecosystem
        AND po2.name       = po.name
        AND po2.version    = po.version
        AND po2.scope      = po.scope
        AND po2.kind       = 'allow'
        AND po2.revoked    = FALSE
  )
ON CONFLICT DO NOTHING;
