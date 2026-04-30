# ADR-004: Per-project license policy override applies in lazy mode

**Status:** Accepted
**Date:** 2026-04-30
**Supersedes:** S-01 anti-spoofing guard from the v1.2 license-policy analysis

## Context

Until v1.2.x, per-project license policy overrides were honored at runtime **only** when `projects.mode == "strict"`. In lazy mode the API rejected `PUT /api/v1/projects/{id}/license-policy` with `mode=override` (403 `strict_required`), and the runtime resolver returned the global policy regardless of the stored override row.

The original rationale (S-01 in the v1.2 license-policy analysis):

> In lazy mode, anyone with a valid PAT can mint a new project label by simply sending a request — the username slot of HTTP Basic Auth becomes the label, and the project row auto-creates. If overrides applied in lazy mode, an attacker could:
>
> 1. Create project `evil` via any proxy request with username `evil`.
> 2. Authenticate against the **admin API** with their PAT and `PUT` an override that allows every license.
> 3. Tag subsequent proxy requests with `evil` and bypass the global license policy.

In practice this rationale conflates two distinct trust boundaries:

1. **Auto-creation of project rows** — gated by `projects.mode`, the PAT identity, and `projects.lazy_create_rate`.
2. **Authoring a per-project license policy** — gated by the **admin API auth** (OIDC bearer or session cookie), which is unrelated to PAT-based proxy traffic.

The S-01 attack chain assumed the same actor could both auto-create labels (PAT → proxy) **and** author overrides (admin OIDC → admin API). In real deployments those are separate identities: only admin operators can hit `PUT /api/v1/projects/{id}/license-policy`, and any operator with that role can already alter the **global** policy. Restricting only the per-project variant to strict mode adds friction without closing a real bypass.

A concrete operational impact reported on 2026-04-30 by valda@cloudfield.cz: deployments that intentionally run in lazy mode (so smoke-test traffic and ad-hoc developer labels just work) cannot grant a single one-off project (e.g. `mvaiag`) a permissive license override without flipping the entire deployment to strict mode and pre-provisioning every label that has ever been used. That is a punitive trade-off for a weak threat model.

## Decision

**Per-project license policy overrides apply in both lazy and strict projects modes.** The deployment-wide `projects.mode` flag no longer gates per-project overrides at the API or the resolver.

Concretely:

- `internal/license/resolver.go` — `Resolver.ResolveForProject` no longer checks `strictMode`; the field and the `ResolverConfig.StrictMode` member are removed. The only short-circuit left is `projectID == 0`, which still falls back to the global policy.
- `internal/api/license_policy.go` — `handlePutProjectLicensePolicy` no longer returns 403 `strict_required`. `handleGetProjectLicensePolicy` no longer sets a `strict_required` flag on the response, and the `effective_source` annotation no longer carries the `(override ignored — projects.mode is 'lazy')` qualifier.
- `internal/api/server.go` + `cmd/shieldoo-gate/main.go` — the now-unused `projectsMode` field, `SetProjectsMode` setter, and the wiring at startup are removed.
- `ui/` — the `strict_required` flag, the `modeOverrideDisabled` prop, the lazy-mode warning banner, and the "(strict projects mode only)" copy are removed. Operators see a single editor regardless of `projects.mode`.

Project auto-creation in lazy mode is unchanged — `projects.max_count`, `projects.lazy_create_rate`, and the label regex remain the only guards on label minting.

## Consequences

**Positive**

- Lazy-mode deployments can grant per-project license exceptions without flipping the whole deployment to strict mode.
- One uniform admin UI for license overrides, regardless of `projects.mode`. No "strict mode required" dead-end.
- Threat model is now described in terms of the **admin API** trust boundary (OIDC), which matches reality: anyone authoring a per-project override already has admin credentials and could equally edit the global policy.

**Negative / accepted risks**

- An attacker who **already holds admin OIDC credentials** can author a permissive license override on any (existing or newly auto-created) project. This is a strict subset of what they can do via the global policy endpoint, so it does not widen the blast radius. Audit log rows for `PUT /api/v1/projects/{id}/license-policy` continue to record the actor.
- Operators who relied on `projects.mode=strict` as an indirect "no per-project license overrides" knob lose that side effect. If they want to forbid overrides, they should remove admin permissions from the relevant operators (or, in the future, introduce a dedicated `policy.licenses.locked: true` flag — out of scope here).

## Migration

- No DB migration required. Existing `project_license_policy` rows authored before this change start being honored at runtime in lazy-mode deployments on first startup after the upgrade. Operators who do **not** want the previously-stored overrides to suddenly take effect should `DELETE /api/v1/projects/{id}/license-policy` for the affected projects before upgrading.
- API: the `strict_required` field is dropped from the `LicensePolicyView` response shape, and the 403 `strict_required` response on PUT no longer occurs. Clients that read `strict_required` should treat its absence as "always false" and fall through to normal mode-selection UX.
- UI: no operator action required.
