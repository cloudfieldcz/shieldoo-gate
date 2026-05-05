# ADR-006: Per-project, per-package policy overrides (whitelist + blacklist)

**Status:** Accepted
**Date:** 2026-05-05
**Builds on:** ADR-004 (per-project license policy override applies in lazy mode)

## Context

Per-project license policy (ADR-004) is coarse — it inherits, overrides, or disables the *whole* policy for a project. The common operational need is finer:

- **Whitelist:** "allow this single GPL-licensed tool in project `acme`, while keeping the GPL block intact for everyone else and for every other package in `acme`."
- **Revert:** "I previously whitelisted `lodash` in project `acme` and need to take that back."
- **Blacklist (symmetric):** "I want to ban `colors` in project `acme` even though it currently passes the global license policy."

The whitelist case is the load-bearing one. The revert case is what surfaced the work — the original report from valda was "I needed to revert white-listing of a package and there was no UI for it." Blacklist follows naturally from the same machinery and is included for symmetry, scoped to packages the project has already pulled (no pre-emptive blacklist-by-name form, see "Out of scope").

We considered but rejected:

- **A new parallel table (`project_policy_overrides`).** Doubles the policy-engine resolution path, fragments the audit story, and makes the typosquat release flow inconsistent with new per-project rows.
- **Reusing `project_license_policy.allowed`/`blocked` lists with package coordinates instead of SPDX expressions.** Conflates two different decision axes and breaks the existing license evaluator. Worse, it would duplicate the override-revocation infrastructure that `policy_overrides` already has.

## Decision

Extend the existing `policy_overrides` table with two columns and add the missing per-project lookup tier:

- `project_id INTEGER REFERENCES projects(id)` — nullable. `NULL` preserves the current global semantics (used by typosquat releases). A non-null value scopes the row to one project.
- `kind TEXT NOT NULL DEFAULT 'allow' CHECK (kind IN ('allow','deny'))` — `allow` = whitelist, `deny` = blacklist. The existing rows (typosquat releases) all become `kind=allow` by default.

The unique-active index becomes `(ecosystem, name, version, scope, COALESCE(project_id, 0), kind) WHERE revoked = FALSE`, so each project may carry at most one active allow + one active deny per `(package, scope)`. The `COALESCE` keeps NULL `project_id` rows distinct from project rows.

Resolution precedence in `internal/policy/engine.go`:

1. Per-project DENY (`project_id = current AND kind = 'deny'`) → BLOCK.
2. Per-project ALLOW (`project_id = current AND kind = 'allow'`) → ALLOW.
3. Global ALLOW (`project_id IS NULL AND kind = 'allow'`) → ALLOW.
4. Fall through to license policy / verdict rules.

The current project is read from `project.FromContext(ctx)` — already populated by the proxy auth middleware. No adapter signatures change.

`HasOverride` is preserved for the typosquat short-circuit but is now an ALLOW-only API: it returns false for DENY rows, so a per-project deny does not silently bypass typosquat detection (it still blocks, just for a different reason).

The cache-hit license path (`EvaluateLicensesOnly`) consults overrides via a JOIN through the `artifacts` table because it only has the opaque `artifact_id` string. The lookup happens **before** the `licenseEnabled` gate so deny overrides bite even when license enforcement is off for the project.

The admin UI surfaces the new mechanism via the existing project Artifacts tab. `GET /api/v1/projects/{id}/artifacts` is extended to merge three sources — pulled artifacts, license-block events from `audit_log`, and active per-project overrides — into one list keyed on `(ecosystem, name, version)` with a `decision` field (`CLEAN | BLOCKED_LICENSE | WHITELISTED | BLACKLISTED`) and contextual action buttons (Whitelist / Blacklist / Revert).

## Consequences

**Positive**

- One unified override mechanism (typosquat releases, per-project license waivers, per-project denies) sharing the same revoke flow and audit story.
- The project Artifacts tab is the single source of truth for per-project policy decisions — admins do not need to navigate to a separate Overrides page.
- Per-project denies survive `mode=disabled` license enforcement, providing a real "always block this here" knob that the existing per-project policy mode could not express.

**Negative / accepted**

- A small read amplification on the cache-hit license path (one extra `artifacts` lookup to recover ecosystem/name/version from the opaque ID). Both the lookup and the override match are indexed; the impact is well under a millisecond on SQLite.
- Per-project deny overrides are absent from the global `/api/v1/overrides` list endpoint by design (those routes remain global-only). Auditing per-project overrides goes through the project artifacts pane and the audit log.
- The unique-active index is rebuilt during migration (table-recreation pattern in SQLite, `ADD COLUMN IF NOT EXISTS` in Postgres). Existing typosquat overrides are preserved with `project_id=NULL, kind='allow'`.

## Out of scope

- Pre-emptive blacklisting of packages a project has never pulled (no free-form "type a package name to ban" form). The Blacklist button only appears on already-pulled `CLEAN` rows. Easy to add if real demand surfaces.
- A third override kind for "silence a license warning" (`warn`-licenses are header-only and non-blocking; YAGNI).
- A global denylist (`project_id NULL + kind='deny'`). The schema permits it but no UI affordance is built — direct API access only, intentionally inconvenient.

## Migration

- SQLite: table recreation (see `migrations/sqlite/026_project_policy_overrides.sql`) — copies all existing `policy_overrides` rows into a v26 table that has `project_id` (NULL for back-compat) and `kind='allow'`. Indexes are recreated. Idempotent under `TestInitDB_Idempotent`.
- Postgres: `ADD COLUMN IF NOT EXISTS` for both new columns plus the rebuilt unique index.
- Existing typosquat releases continue to work unchanged — they keep `project_id=NULL` and `kind='allow'`, so `HasOverride` finds them in the third (global ALLOW) tier.
