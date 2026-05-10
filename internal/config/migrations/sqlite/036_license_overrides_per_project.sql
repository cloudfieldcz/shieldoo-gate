-- 036_license_overrides_per_project.sql (sqlite)
-- Backfill currently-active global "manual release" overrides into per-project
-- rows. Globals stay (revoked=0) for compatibility; per-project copies give
-- operators per-project visibility + isolated revoke. New license-block
-- releases go straight to per-project (handler change in artifacts.go forces
-- the global Release endpoint to 409 with a project-scope hint).
--
-- Why over-inclusive (all 'manual release', not just license-related):
-- today's schema doesn't record *why* an artifact was originally blocked at
-- the time the global override was created. We can't reconstruct that. So we
-- migrate every active 'manual release' row — scan-released artifacts also
-- gain per-project allow rows; that's fine because the global still wins
-- anyway, and the per-project rows give operators visibility on Project Detail.
--
-- Idempotent: NOT EXISTS guard prevents duplicates on re-run; ON CONFLICT
-- DO NOTHING covers any race against concurrent inserts hitting the unique
-- partial index idx_policy_overrides_unique_active.
--
-- Migrated rows are tagged with created_by='migration:036' so an operator can
-- bulk-revoke them later (`UPDATE policy_overrides SET revoked=1 WHERE created_by='migration:036'`).

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
    0 AS revoked
FROM policy_overrides po
CROSS JOIN projects p
WHERE po.project_id IS NULL
  AND po.revoked = 0
  AND po.reason = 'manual release'
  AND NOT EXISTS (
      SELECT 1 FROM policy_overrides po2
      WHERE po2.project_id = p.id
        AND po2.ecosystem  = po.ecosystem
        AND po2.name       = po.name
        AND po2.version    = po.version
        AND po2.scope      = po.scope
        AND po2.kind       = 'allow'
        AND po2.revoked    = 0
  )
ON CONFLICT DO NOTHING;
