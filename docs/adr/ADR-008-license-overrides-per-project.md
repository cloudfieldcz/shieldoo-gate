# ADR-008 — License overrides are per-project, not global

**Status:** Accepted
**Date:** 2026-05-08
**Supersedes:** Behaviour established by ADR-006 + migration 026 where the
artifact-detail "Release" button wrote a global `policy_overrides` row for
**every** quarantine reason, including license blocks.

## Context

License decisions are project-scoped. Project A may forbid GPL-3.0 while
project B explicitly relies on it. Pre-2026-05 the artifact-detail Release
endpoint (`POST /api/v1/artifacts/{id}/release`) wrote into the global
`policy_overrides` table (`project_id IS NULL`) regardless of why the artifact
was quarantined. For typosquat / scanner releases that is the correct blast
radius: the artifact bytes themselves are the same everywhere. For a license
block it is wrong — releasing GPL-3.0 lodash for project A also unblocks it for
project B.

The infrastructure for per-project overrides has been in place since
**migration 026** (`policy_overrides.project_id`, `policy_overrides.kind`,
`POST /api/v1/projects/{id}/overrides`) and ADR-006. The artifact-detail UX
just never used it.

We considered four alternatives:

1. **Block license releases entirely from the artifact-detail page** — too
   sharp; operators have a real workflow that needs the button somewhere.
2. **Make `POST /api/v1/artifacts/{id}/release` infer the project from
   `audit_log.LICENSE_BLOCKED` events** — opaque (the operator can't see which
   project they are releasing for) and breaks when multiple projects pulled
   the same artifact.
3. **Auto-fanout: write a per-project allow row for every project that has
   ever pulled the artifact** — silently inverts every other project's
   license policy. Hard no per the security invariants.
4. **Refuse the global call with a hint pointing to the per-project endpoint**
   — explicit, audit-trail-friendly, requires zero schema changes. Chosen.

## Decision

1. **License-block releases go through the per-project endpoint.**
   `POST /api/v1/projects/{id}/overrides` with `kind=allow` is the canonical
   home for license waivers.
2. **The global Release endpoint refuses license-flavoured quarantines** with
   `HTTP 409` and a structured `next_action` body
   (`{ error: "license_block_requires_project_scope", next_action: { type,
   endpoint, method, hint } }`). The predicate that decides "is this a license
   block?" is `internal/api/license_predicate.go:isLicenseQuarantineReason`,
   which reuses the `licenseQuarantineReasonPrefix = "license policy:"`
   constant from `internal/api/license_reevaluation.go` (single source of
   truth — adding a new license-quarantine reason in one place automatically
   gates the global Release).
3. **Project Detail surfaces the per-project view.** A new
   `ProjectLicenseOverridesPanel` component renders active per-project allow
   /deny rows fetched from `GET /api/v1/projects/{id}/overrides` (added in
   this same change), with a per-row Revoke. The Artifact Detail panel swaps
   its Release button for an info banner when the artifact is
   license-quarantined.
4. **Migration 036 backfills active global "manual release" overrides** to
   per-project rows. For every existing project, every active global
   `manual release` row is mirrored as a per-project allow with
   `created_by='migration:036'`. Globals stay (revoked=FALSE) so the lookup
   still falls through if a per-project allow is later revoked.
5. **Other quarantine reasons keep the existing global flow.** Typosquat and
   scanner-verdict releases reflect properties of the artifact itself, not a
   project's policy, so they continue to write `project_id IS NULL` rows.

## Consequences

### Positive

- Correct blast radius: a license waiver in project A no longer affects
  project B.
- Audit trail per project: every license decision is visible from the project
  it affects, with `created_by` populated from the OIDC user (or
  `migration:036` for backfilled rows).
- No schema change beyond migration 036 — reuses the existing
  `policy_overrides.project_id` column added by migration 026.
- The `licenseQuarantineReasonPrefix` constant is the single point at which
  a new license-flavoured reason needs to be registered to participate in the
  409 gate.

### Negative

- Migration 036 is **over-inclusive**: it copies all active `manual release`
  rows, not just license-related ones, because the original block reason
  isn't recorded on the override row. This is acceptable — the global still
  wins via the `COALESCE(project_id, 0)`-aware unique index, and operators
  get one extra per-project row to revoke if undesired. The trade-off is
  preferable to losing a release-precedent at migration time.
- Existing automation that POSTs to `/api/v1/artifacts/{id}/release` against
  license-quarantined artifacts now receives **409** instead of 200. The
  error body's `next_action.endpoint` carries the new path so a parser-aware
  client can self-redirect; pre-existing clients need a one-time update. The
  E2E shell tests cover both paths.

### Neutral

- The global `policy_overrides` table is now bimodal: global rows still exist
  and are still authoritative for typosquat / scanner release; per-project
  rows are layered on top for license decisions. Documentation calls out the
  distinction in [`docs/policy.md`](../policy.md#override-tiers) and
  [`docs/data-model.md`](../data-model.md#license-block-releases-live-per-project-migration-036).

## Alternatives considered

See "Context" above. The four alternatives were:

- Block license releases entirely → rejected as too sharp.
- Auto-infer the project from `audit_log` → rejected as opaque + ambiguous.
- Auto-fanout to all projects that pulled the artifact → rejected as a
  silent policy inversion.
- 409 + per-project endpoint → adopted.

## Implementation pointers

- `internal/api/license_predicate.go` — `isLicenseQuarantineReason` predicate
- `internal/api/artifacts.go` — 409 response body
- `internal/api/projects.go` — `handleListProjectOverrides` (new)
- `ui/src/components/projects/ProjectLicenseOverridesPanel.tsx` — UI panel
- `ui/src/components/artifacts/ArtifactDetailPanel.tsx` — replaces Release
  button with hint when license-quarantined
- `internal/config/migrations/{sqlite,postgres}/036_license_overrides_per_project.sql`
  — backfill migration

## See also

- [ADR-006 — Per-project package overrides](ADR-006-per-project-package-overrides.md) — schema + endpoint that ADR-008 now wires into the artifact-detail UX.
- [ADR-004 — License policy override in lazy mode](ADR-004-license-policy-override-in-lazy-mode.md) — earlier license-policy semantics.
- [`docs/policy.md`](../policy.md#policy-overrides) — override tiers and resolution precedence.
- [`docs/data-model.md`](../data-model.md#license-block-releases-live-per-project-migration-036) — migration 036 schema notes.
