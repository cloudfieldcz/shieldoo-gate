# Vulnerability Scan — Final Polish — Phase 6: Documentation + IMPLEMENTATION_STATUS update

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring docs in line with what shipped in Phases 1–5. Per CLAUDE.md "documentation is the source of truth", every API/CLI/UI surface added must be documented; otherwise the next reader can't find it.

**Architecture:** No code, all markdown / OpenAPI / status-file updates. Concentrated commits per doc family so reviewers can scan the diff at a glance.

**Index:** [`plan-index.md`](./2026-05-08-vuln-scan-finish-plan-index.md)

**Depends on:** Phases 1–5 (so the docs reference final flag names + endpoint shapes).

---

## File map

| Path | Action | Responsibility |
|------|--------|----------------|
| `docs/cli/shdg.md` | Create | Full CLI reference (subcommands, flags, env vars, exit codes, examples). |
| `docs/index.md` | Modify | Add CLI doc entry; nudge `IMPLEMENTATION_STATUS` reference. |
| `docs/features/vulnerability-scan.md` | Modify | Add CLI-based ingestion section; current section talks only about CI curl. |
| `docs/api/openapi.yaml` | Modify | Add: `GET /api/v1/projects/{id}/overrides` (Phase 5 Task 4b) and the 409 schema for `POST /api/v1/artifacts/{id}/release`. CLI itself isn't an API surface — no entry there. |
| `docs/configuration.md` | Modify | Document the new env vars + Trivy cache directory; nothing for license overrides (UX-only). |
| `docs/data-model.md` | Modify | Note that `policy_overrides.project_id != NULL` is now the canonical home for license-block releases (not new schema, just clarification). |
| `docs/adr/ADR-008-license-overrides-per-project.md` | Create | New ADR documenting the Phase 5 architectural decision. |
| `docs/features/license-policy.md` (or `docs/features/projects.md`) | Modify | Document the per-project Release UX. |
| `docs/plans/2026-05-07-vulnerability-scan/IMPLEMENTATION_STATUS.md` | Modify | Mark all 🟡/❌ items now complete; correct the "frontend test infrastructure not in this branch" misstatement; add Phase 5 line. |
| `README.md` | Modify | One-line CLI mention pointing at `docs/cli/shdg.md`. |

---

## Task 1: `docs/cli/shdg.md` — full CLI reference

**Files:**
- Create: `docs/cli/shdg.md`

- [ ] **Step 1: Write the doc**

Cover at minimum these sections (paste from final flag set):

```markdown
# `shdg` — Shieldoo Gate CLI

`shdg` is a small CI helper that uploads CycloneDX SBOMs to a Shieldoo Gate
deployment for vulnerability scanning. It generates the SBOM itself (via a
pinned Trivy that it auto-downloads on first run) or accepts a pre-built
file via `--sbom`.

## Install

> Pre-built binaries are not yet published. Build from source:
>
> ```bash
> git clone https://github.com/cloudfieldcz/shieldoo-gate.git
> cd shieldoo-gate
> make build-shdg
> sudo cp bin/shdg /usr/local/bin/
> ```

## Subcommands

### `shdg scan`

Generate (or re-use) a CycloneDX SBOM and upload it.

| Flag | Type | Default | Notes |
|------|------|---------|-------|
| `--project` | string | — (required) | Project label as configured in the gate. |
| `--component` | string | — (required) | Logical component name. Lazy-created on first upload. |
| `--sbom` | path | (none — generate) | Skip Trivy and upload this file as-is. |
| `--ecosystem` | enum | `auto` | `auto`, `pypi`, `npm`, `docker`, `go`, `multi`. |
| `--dir` | path | `.` | Project directory to scan when generating. |
| `--wait` | bool | `false` | Poll `/scan-runs/{id}` until terminal status. |
| `--fail-on` | enum | `none` | `critical`, `high`, `none`. Requires `--wait`. |
| `--timeout` | duration | `10m` | Wait timeout (Go duration string). |
| `--poll-interval` | duration | `2s` | Polling cadence when waiting. |
| `--verbose` | bool | `false` | Verbose stderr logging. |

### `shdg version`

Prints `shdg <semver> (<commit>) — <go-version> <os>/<arch>`.

## Environment

- `SHIELDOO_TOKEN` — PAT with `scan:upload` scope (or the global super-token). Required for `scan`.
- `SHIELDOO_URL` — Base URL of the gate (e.g. `https://gate.example.com`). Required for `scan`.
- `SHDG_CACHE_DIR` — Override the Trivy cache directory (default `~/.cache/shdg`).

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Upload accepted (or, with `--wait` + `--fail-on=none`, terminal succeeded) |
| 1 | Generic error (network, file I/O, gate 5xx, OR `--fail-on critical/high` matched) |
| 2 | Bad CLI args (missing required flags, invalid ecosystem, missing env) |
| 3 | Scan run terminal status was `failed` or `cancelled` |
| 4 | Polling timed out before terminal status |

## Examples

…(GitHub Actions, GitLab CI, generic curl-equivalent — match `IntegrationGuide.tsx`).
```

- [ ] **Step 2: Commit**

```bash
git add docs/cli/shdg.md
git commit -m "docs(cli): shdg reference (subcommands, flags, env, exit codes)"
```

---

## Task 2: `docs/features/vulnerability-scan.md` — add CLI section

**Files:**
- Modify: `docs/features/vulnerability-scan.md`

- [ ] **Step 1: Add a "CLI ingestion" section**

Insert above the existing "CI ingestion" section (or rename to "CLI vs. raw curl"). Lead with the CLI as the recommended path:

```markdown
## CLI ingestion (recommended)

Use the `shdg` CLI from your CI pipeline:

\`\`\`bash
SHIELDOO_TOKEN=$SHIELDOO_TOKEN \\
SHIELDOO_URL=https://gate.example.com \\
shdg scan --project myproj --component web --wait --fail-on critical
\`\`\`

`shdg` auto-detects ecosystem (Dockerfile/go.mod/package.json/requirements.txt/pyproject.toml),
generates the SBOM via a bundled Trivy v0.58.1, and uploads. With `--wait` it polls
the resulting scan run and exits non-zero when new criticals appear, gating CI.

See [`docs/cli/shdg.md`](../cli/shdg.md) for the full reference.

## Raw curl ingestion

For environments where adding a binary isn't desirable, the same upload happens
over plain curl:

\`\`\`bash
trivy fs --format cyclonedx --output sbom.json .
curl -fsS -X POST \\
  -H "Authorization: Bearer $SHIELDOO_TOKEN" \\
  -H "Content-Type: application/vnd.cyclonedx+json" \\
  --data-binary @sbom.json \\
  https://gate.example.com/api/v1/projects/myproj/components/web/scans
\`\`\`
```

- [ ] **Step 2: Commit**

```bash
git add docs/features/vulnerability-scan.md
git commit -m "docs(vuln-scan): add CLI ingestion section (recommended path)"
```

---

## Task 3: OpenAPI updates

**Files:**
- Modify: `docs/api/openapi.yaml`

Add (after Phase 5 ships):

- `GET /api/v1/projects/{id}/overrides` (if added by Phase 5 Task 4b).
- 409 response schema on `POST /api/v1/artifacts/{id}/release` with `error` + `next_action.{endpoint, method, hint}`.

- [ ] **Step 1: Locate the existing `/api/v1/projects/{id}/overrides` POST entry**

```bash
grep -n "/projects/{id}/overrides" docs/api/openapi.yaml
```

Mirror its shape, swap `post` for `get`, response is `200` with `items: array<ProjectOverride>`.

- [ ] **Step 2: Add the 409 to release**

```bash
grep -n "/artifacts/{id}/release" docs/api/openapi.yaml
```

Under `responses:`, add:

```yaml
'409':
  description: Artifact was license-blocked; release must be project-scoped.
  content:
    application/json:
      schema:
        type: object
        required: [error, next_action]
        properties:
          error:
            type: string
            example: license_block_requires_project_scope
          next_action:
            type: object
            properties:
              endpoint: { type: string }
              method: { type: string }
              hint: { type: string }
```

- [ ] **Step 3: Lint**

```bash
npx --yes @redocly/cli lint docs/api/openapi.yaml
```

Expected: 0 errors.

- [ ] **Step 4: Commit**

```bash
git add docs/api/openapi.yaml
git commit -m "docs(openapi): GET /projects/{id}/overrides + 409 on artifact release"
```

---

## Task 4: ADR-008

**Files:**
- Create: `docs/adr/ADR-008-license-overrides-per-project.md`

- [ ] **Step 1: Draft the ADR**

```markdown
# ADR-008 — License overrides are per-project, not global

**Status:** Accepted (2026-05-08)
**Supersedes:** Behaviour established by ADR-006 / migration 002 where all manual releases wrote to global `policy_overrides`.

## Context

License decisions are project-scoped: project A may forbid GPL-3.0 while
project B allows it. Pre-2026-05 the artifact-detail "Release" button wrote
to the global `policy_overrides` table regardless of why the artifact was
quarantined. This had the wrong blast radius — releasing a GPL-3.0 package
for project A also allowed it for project B.

The infrastructure for per-project overrides (`policy_overrides.project_id`,
`POST /api/v1/projects/{id}/overrides`) had been in place since migration
026, but the artifact-detail UX never used it.

## Decision

1. License-block releases go through `POST /api/v1/projects/{id}/overrides`
   (kind=allow). The artifact-detail global Release endpoint returns 409 when
   the current `quarantine_reason` indicates a license block.
2. The Project Detail page lists active per-project overrides and the
   per-row Release button on license-blocked artifact rows.
3. Migration 036 backfills currently-active global `manual release`
   overrides into per-project rows for every project (additive — globals
   stay for audit, but operators get per-project visibility).
4. Other quarantine reasons (typosquat, scanner verdict) keep the existing
   global Release flow — those reflect properties of the artifact itself,
   not a project's policy.

## Consequences

- New code paths: `isLicenseQuarantineReason`, `handleListProjectOverrides`,
  `ProjectLicenseOverridesPanel` UI.
- Old code paths preserved for non-license quarantines.
- Migration 036 is over-inclusive (copies all `manual release`, not just
  license-related, because the original block reason isn't recorded). This
  is acceptable: the global still wins via the COALESCE-aware unique index,
  and operators get one extra per-project row to revoke if undesired.
- Documentation: project-detail UX in `docs/features/projects.md`; reference
  to per-project overrides in `docs/data-model.md`.
```

- [ ] **Step 2: Cross-link from `docs/index.md`**

Add a row to the ADR list pointing at ADR-008.

- [ ] **Step 3: Commit**

```bash
git add docs/adr/ADR-008-license-overrides-per-project.md docs/index.md
git commit -m "docs(adr): ADR-008 license overrides are per-project (Phase 5)"
```

---

## Task 5: `docs/configuration.md` + `docs/data-model.md`

**Files:**
- Modify: `docs/configuration.md`
- Modify: `docs/data-model.md`

- [ ] **Step 1: Add to `configuration.md`**

A short section listing the new CLI env vars + Trivy cache:

```markdown
### `shdg` CLI runtime

| Env | Default | Notes |
|-----|---------|-------|
| `SHIELDOO_TOKEN` | — | PAT with scope `scan:upload`, or global super-token. |
| `SHIELDOO_URL` | — | Base URL of the gate (e.g. `https://gate.example.com`). |
| `SHDG_CACHE_DIR` | `~/.cache/shdg` | Where the bundled Trivy v0.58.1 binary is cached after first download. |
```

- [ ] **Step 2: Update `data-model.md`** with one paragraph clarifying the `policy_overrides` shape post-Phase 5:

```markdown
> **License-block releases:** rows where `project_id IS NOT NULL AND kind='allow'`
> are the canonical home for license-policy releases (since 2026-05). Older rows
> with `project_id IS NULL` are kept for audit; they are also backfilled per-project
> by migration 036.
```

- [ ] **Step 3: Commit**

```bash
git add docs/configuration.md docs/data-model.md
git commit -m "docs: shdg CLI env + per-project license override clarification"
```

---

## Task 6: `IMPLEMENTATION_STATUS.md`

**Files:**
- Modify: `docs/plans/2026-05-07-vulnerability-scan/IMPLEMENTATION_STATUS.md`

- [ ] **Step 1: Update the verification table** with the new test counts (re-run E2E and paste the actual PASS/FAIL/SKIP numbers).

- [ ] **Step 2: Walk through phases and flip 🟡/❌ → ✅** for items completed in this finish-pass:

  - Phase 2: per-ecosystem E2E variants → ✅
  - Phase 3: panic-redaction E2E (now log_redaction E2E with `log_skip` semantics) → ✅
  - Phase 6: Playwright XSS / happy-path E2E → ✅
  - Phase 7: AI bridge SSRF E2E → ✅
  - Phase 8: CLI subcommand → ✅ (delivered as `cmd/shdg/`)
  - Cross-cutting: super-token-audit E2E → ✅
  - Cross-cutting: per-project license override scoping → ✅ (new entry)

- [ ] **Step 3: Fix the "frontend test infrastructure not in this branch" misstatement** (line 331 of the source file). Replace with:

  > Frontend test infrastructure (`ui/playwright.config.ts` + 2 existing specs) is in the branch — `ui/e2e/vuln-scan.spec.ts` ships in 2026-05-08 final pass.

- [ ] **Step 4: Add a new "How this plan finished" closing section** linking to the `2026-05-08-vuln-scan-finish` plan files for traceability.

- [ ] **Step 5: Commit**

```bash
git add docs/plans/2026-05-07-vulnerability-scan/IMPLEMENTATION_STATUS.md
git commit -m "docs(vuln-scan): IMPLEMENTATION_STATUS — final pass (CLI + E2E + license per-project)"
```

---

## Task 7: README.md one-liner

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a single-line CLI mention** under the existing feature bullet list:

```markdown
- `shdg` CLI for CI vulnerability-scan ingestion — see [docs/cli/shdg.md](docs/cli/shdg.md).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(readme): mention shdg CLI"
```

---

## Phase 6 verification

- [ ] **Step 1: All docs render**

```bash
npx --yes @redocly/cli lint docs/api/openapi.yaml
```

Expected: 0 errors.

- [ ] **Step 2: Visit relative links manually**

Open `docs/index.md`, click each newly-added link (CLI doc, ADR-008). All should resolve.

- [ ] **Step 3: Final make check**

```bash
go build ./... && go test ./... -race && cd ui && npm run build && cd ../scanner-bridge && uv run pytest
make test-e2e-containerized
```

All four E2E runs zero-fail. Branch is now demonstrably merge-ready and the docs match shipped behaviour.
