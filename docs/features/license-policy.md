# License Policy Enforcement

> Block or warn on artifacts whose declared licenses violate your organization's policy.

**Status:** Implemented (v1.2)
**Analysis:** [2026-04-15-sbom-and-license-policy.md](../plans/2026-04-15-sbom-and-license-policy.md)

## Problem

Many organizations have strict rules about which open-source licenses are acceptable. A developer pulling in a GPL-3.0 dependency into a proprietary codebase can create legal liability. Before v1.2, Shieldoo Gate focused on security (malicious content) but did not enforce license compliance.

## Does license policy depend on projects?

Yes, but only at the per-project-override level. **Global license policy applies to every artifact, regardless of which project the request belongs to.** Deployments that don't care about projects can set the global lists and never touch [project registry](./projects.md) — all requests land under the `default` project (seeded by migration 018) and inherit the global policy.

If you run in [strict mode](./projects.md#strict) and explicitly provision projects, you can additionally define per-project overrides for licenses that are acceptable in one project but not another (e.g. allow `GPL-3.0-only` in an internal `oss-playground` project but keep it blocked for `commercial-svc`). See [Per-Project Overrides](#per-project-overrides) below.

## How It Works

License enforcement is a new step in the policy engine that runs **after the static allowlist but before verdict aggregation**. The effective policy for each artifact is computed from:

1. **Global YAML policy** — `policy.licenses.*` in `config.yaml`.
2. **Per-project override** — optional row in `project_license_policy`, keyed by `project_id`.

**Security guard:** per-project overrides are only honored at runtime when `projects.mode == "strict"`. In lazy mode, anyone can pick any project label (it's the Basic auth username), so honoring a permissive override would be a trivial policy bypass. The API rejects `PUT .../license-policy` with `mode=override` in lazy mode (403).

### Pipeline Position

```
Evaluate(ctx, artifact, scanResults):
  1. DB override (highest priority — allow)
  2. Static allowlist → allow
  3. ★ License policy:
       - get licenses from scanResults (fast path)
       - fallback to sbom_metadata.licenses_json
       - if no licenses → apply on_sbom_error
       - evaluate → block | warn | allow
  4. Aggregate findings (CLEAN | SUSPICIOUS | MALICIOUS)
  5. Mode-based decision (strict | balanced | permissive)
```

A blocked license short-circuits the pipeline — scan findings cannot override a legally-blocked license.

### SPDX Matching

- **Simple IDs:** `MIT`, `Apache-2.0`, `GPL-3.0-only`. Case-insensitive per SPDX spec.
- **Expressions:** `MIT OR Apache-2.0`, `(MIT OR Apache-2.0) AND BSD-3-Clause`, `Apache-2.0 WITH LLVM-exception`.
  - `OR` semantics are configurable: `any_allowed` (default) or `all_allowed`.
  - `AND` requires all leaves to pass.
  - `WITH` modifiers are preserved in the AST but ignored during evaluation (v1.2 limitation — documented).
- **Aliases:** ~30 common non-SPDX strings are normalized on ingest (`"Apache License 2.0"` → `Apache-2.0`, `"MIT License"` → `MIT`, etc.). See [internal/sbom/parser.go](../../internal/sbom/parser.go).

### Unknown Licenses

Licenses that are not SPDX IDs (and don't match an alias) fall through to the configured `unknown_action`:

- `allow` (default) — pass silently.
- `warn` — pass but emit `LICENSE_WARNED` audit event + `X-Shieldoo-Warning` header.
- `block` — reject with 403.

## Configuration

```yaml
policy:
  licenses:
    enabled: true
    blocked:                 # SPDX IDs to always block
      - GPL-3.0-only
      - AGPL-3.0-only
    warned:                  # Allow but emit warning
      - LGPL-2.1-only
      - MPL-2.0
    allowed:                 # Whitelist mode when non-empty
      - MIT
      - Apache-2.0
      - BSD-3-Clause
    unknown_action: allow    # allow | warn | block
    on_sbom_error: allow     # action when SBOM is unavailable
    or_semantics: any_allowed # any_allowed | all_allowed
```

### on_sbom_error

Controls behavior when an artifact has no SBOM data (e.g. version-diff re-evaluation, pre-v1.2 artifact, or Trivy timeout):

- `allow` — skip license check, add `"license: SBOM unavailable"` warning.
- `warn` — same as allow but also emit `LICENSE_CHECK_SKIPPED` audit.
- `block` — reject with 403. Use only when your threat model requires it — a Trivy outage would turn every proxy request into a 403.

## Per-Project Overrides

In **strict** projects mode only:

```http
PUT /api/v1/projects/{id}/license-policy
Content-Type: application/json

{
  "mode": "override",
  "blocked": [],
  "allowed": ["GPL-3.0-only", "MIT", "Apache-2.0"],
  "unknown_action": "warn"
}
```

Modes:

- `inherit` (default) — use global policy.
- `override` — replace global with the rows in this record. **Requires strict mode.**
- `disabled` — skip license check entirely for this project.

The `GET` view surfaces a `strict_required` boolean and an annotated `effective_source` so the UI can explain why an override is ignored in lazy mode.

## Runtime-mutable global policy (v1.2.1+)

The global policy is loaded from `policy.licenses.*` in `config.yaml` at startup, but can be **edited at runtime** from the admin UI (or via API) — values are persisted in the `global_license_policy` table (migration 023, singleton row `id = 1`) and applied to the live resolver without a restart.

Resolution order on startup:

1. Read `policy.licenses.*` from YAML → seed the resolver's in-memory global policy.
2. Try `SELECT * FROM global_license_policy WHERE id = 1`. If a row exists, **override** the seeded values with the DB values (including `on_sbom_error`).
3. If no row exists, the YAML values stay in effect.

On `PUT /api/v1/policy/licenses`:

1. Validate + upsert the singleton row.
2. Push the new `license.Policy` into `Resolver.SetGlobal(...)` — this also purges the per-project LRU cache so projects inheriting the global see the change immediately.
3. Push the new `on_sbom_error` into `Engine.SetOnSBOMError(...)`.
4. Return the refreshed view (`GET /api/v1/policy/licenses`).

The `GET` response includes a `source` field (`"db"` or `"config"`) so the UI can show whether the live values are coming from a runtime edit or from the YAML fallback.

> **Scope:** The DB row overrides the blocked/warned/allowed lists, `unknown_action`, `on_sbom_error`, and `or_semantics`. It does **not** yet override `policy.licenses.enabled`: the master on/off switch is still file-controlled (set `policy.licenses.enabled: false` in `config.yaml` to disable the whole feature).

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/policy/licenses` | Effective global policy (blocked/warned/allowed, unknown_action, on_sbom_error, or_semantics, source=db\|config) |
| PUT | `/api/v1/policy/licenses` | Upsert global policy — applied live, no restart |
| DELETE | `/api/v1/policy/licenses` | Revert to YAML fallback (purges DB row + per-project cache; subsequent GET returns `source=config`) |
| GET | `/api/v1/projects/{id}/license-policy` | Effective policy view with inheritance annotation |
| PUT | `/api/v1/projects/{id}/license-policy` | Upsert override (returns 403 in lazy mode when mode=override) |
| DELETE | `/api/v1/projects/{id}/license-policy` | Remove override → fall back to inherit (evicts cached entry) |
| GET | `/api/v1/artifacts/{id}/licenses` | Pre-extracted SPDX IDs for a specific artifact |

## Admin UI

Two entry points in the sidebar:

- **License Policy** (`/license-policy`) — edits the **global** policy. The editor:
  - Shows `Source: db | config` so you know whether a runtime edit is active or the YAML fallback is in effect.
  - **License-group presets** — a table of curated SPDX groups (Strong copyleft GPL, Network copyleft AGPL, Weak copyleft LGPL/MPL/EPL, Permissive MIT/Apache/BSD/ISC, Public domain, Creative Commons). Clicking `Block` / `Warn` / `Allow` on any row writes all group SPDX IDs into that bucket and removes them from the other two. This is the "block all copyleft" one-click UX.
  - **Bucket editors** — three coloured sections (Block, Warn, Allow) with pill-badges of the current SPDX IDs. Add via a `<datalist>`-backed input (autocomplete over the ~100 common SPDX IDs). Unrecognized strings are still accepted (Trivy might emit them verbatim) but flagged with a small `?` marker.
  - **Unknown license** / **Missing SBOM** / **OR-expression semantics** — select inputs mapped to `unknown_action`, `on_sbom_error`, and `or_semantics`.
  - **Save policy** writes to the `global_license_policy` row and pushes to the live resolver + engine (no restart).

- **Projects › project detail › License policy tab** (`/projects/:id`) — edits the **per-project** override. Same editor, but with an extra mode radio (`inherit` / `override` / `disabled`). In lazy mode the `override` radio is disabled with a tooltip that explains the S-01 strict-mode requirement.

**No wildcard matching.** The editor is explicit by design: presets expand into concrete SPDX IDs at save time, so the persisted policy can be audited without surprises. If you later need to cover a new GPL variant, you update this editor's group definition and re-save — no silent broadening.

Pre-extracted license identifiers are visible in each artifact detail panel under **Licenses** (from `sbom_metadata.licenses_json`); the section is hidden for artifacts that pre-date SBOM generation or that had no SBOM emitted by Trivy.

## Audit Events

New event types:

- `LICENSE_BLOCKED` — request rejected due to license policy.
- `LICENSE_WARNED` — license matched warn list; artifact served with `X-Shieldoo-Warning`.
- `LICENSE_CHECK_SKIPPED` — no SBOM available; `on_sbom_error: warn`.

Existing audit infrastructure stamps `project_id` on every row for filtering.

## Error Response

License-blocked requests return HTTP 403 with a JSON body:

```json
{
  "error": "blocked",
  "artifact": "pypi:example-pkg:1.0.0",
  "reason": "license \"GPL-3.0-only\" blocked by global policy"
}
```

Plus the existing `X-Shieldoo-Reason` header (emitted by the generic block path).

## Maven Effective-POM Resolution

Most Maven JARs (~95%) inherit their `<licenses>` from a parent POM rather than declaring them inline. Shieldoo Gate includes an **effective-POM resolver** that walks the parent chain to discover these inherited licenses.

**How it works:** Before scanning a `.jar`, the Maven adapter calls the effective-POM resolver with the artifact's GAV coordinates. The resolver fetches the standalone `.pom` from the upstream repository, checks for `<licenses>`, and if not found follows the `<parent>` reference up the chain (up to 5 levels, configurable). Results are cached in-memory (LRU, 24h TTL) and merged into the scan result.

**Configuration** (`upstreams.maven_resolver`):

| Field             | Default | Description                                      |
|-------------------|---------|--------------------------------------------------|
| `enabled`         | `true`  | Enable/disable parent chain resolution            |
| `cache_size`      | `4096`  | In-memory LRU cache entries                       |
| `cache_ttl`       | `24h`   | Cache entry TTL (parent POMs are immutable per release) |
| `max_depth`       | `5`     | Max parent chain depth (hard ceiling: 10)         |
| `fetch_timeout`   | `3s`    | Per-POM HTTP timeout                              |
| `resolver_timeout`| `5s`    | Total timeout for entire parent chain walk        |

**Security:** POM XML parsing enforces a 1 MB body size cap (prevents XML bombs), strips DOCTYPE declarations, handles ISO-8859-1/Windows-1252 encodings, and rejects cross-host redirects.

**Fail-open:** Network failures, timeouts, and depth-limit violations result in an empty license list (not an error). The artifact proceeds through the normal scan path with whatever licenses Trivy/extractor discovered.

## Known Limitations

- `WITH` exceptions in SPDX expressions are ignored for evaluation purposes.
- License policy changes are **not retroactive** — already-cached artifacts keep their original verdict. Admins can force re-evaluation via the rescan scheduler.
- License data depends on Trivy's extraction quality. Packages with no declared license surface as empty and fall through to `unknown_action`.
- Per-project overrides require `projects.mode=strict`. Lazy mode deployments can only use the global policy.
- Maven effective-POM resolver requires network access to the upstream Maven repository. Private repositories with authentication are supported (resolver shares the adapter's HTTP client).

## Files

- Evaluator: [internal/license/evaluator.go](../../internal/license/evaluator.go)
- Expression parser: [internal/license/expression.go](../../internal/license/expression.go)
- Resolver (global + project, runtime-mutable): [internal/license/resolver.go](../../internal/license/resolver.go) — `SetGlobal` purges the per-project cache
- Policy engine integration: [internal/policy/engine.go](../../internal/policy/engine.go) — `SetOnSBOMError` for runtime updates
- Per-project API: [internal/api/license_policy.go](../../internal/api/license_policy.go)
- Global API + DB-first loader: [internal/api/global_license_policy.go](../../internal/api/global_license_policy.go)
- Maven effective-POM resolver: [internal/maven/effectivepom/](../../internal/maven/effectivepom/) — `resolver.go` (parent chain walker), `parser.go` (POM XML parser with security protections), `cache.go` (LRU + TTL)
- License alias map: [internal/sbom/parser.go](../../internal/sbom/parser.go) — `NameAliasToID()` normalizes Maven license strings (e.g. "The GNU General Public License, v2 with Universal FOSS Exception, v1.0" → `GPL-2.0-only`)
- Migrations:
  - [022_project_license_policy.sql](../../internal/config/migrations/sqlite/022_project_license_policy.sql) (+ postgres mirror)
  - [023_global_license_policy.sql](../../internal/config/migrations/sqlite/023_global_license_policy.sql) (+ postgres mirror) — singleton row `id = 1`
