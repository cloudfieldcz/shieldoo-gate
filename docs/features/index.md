# Planned Features

> [!IMPORTANT]
> ## Instructions for Ralph (AI Agent)
>
> These rules are **non-negotiable**. Follow them for every feature in this document.
>
> ### 1. Always use skills and make plans
> - **Before writing any code**, invoke the relevant skill (analysis, TDD, debugging, etc.). No exceptions.
> - **Create an implementation plan** (`cf-powers:writing-plans`) and get it reviewed before touching code.
> - Use `cf-powers:analysis` for every new feature — it produces the technical analysis that drives implementation.
> - Use `cf-powers:test-driven-development` — write tests first, then implementation.
> - Use `cf-powers:verification-before-completion` before claiming anything is done.
>
> ### 2. Always update `docs/`
> - Every code change **MUST** include corresponding documentation updates in `docs/`.
> - New features require a new doc page linked from `docs/index.md`.
> - API changes must update `docs/api/openapi.yaml`.
> - Architecture decisions go in `docs/adr/`.
> - **Do not defer docs to "later" — update them as you go.**
>
> ### 3. Always create E2E tests
> - Every implemented feature **MUST** have E2E tests covering **all scenarios** — happy path, error cases, edge cases.
> - For backend/proxy features: write Go E2E tests in `tests/e2e/` and shell-based tests in `tests/e2e-shell/`.
> - For UI features: use **Playwright** to validate the admin UI.
> - E2E tests are the **only reliable way** to verify functionality works end-to-end.
> - Run and verify with:
>   ```
>   make test-e2e-containerized
>   ```
> - **If E2E tests don't pass, the feature is not done.**
>
> ### 4. Branch & commit strategy
> - **Create a feature sub-branch** for each feature you work on.
> - Branch naming: `feature/<feature-short-name>` from the **current branch** (branches chain from each other).
>   - Examples: `feature/cli-cicd-integration`, `feature/package-provenance`, `feature/dependency-graph`
> - **Commit early and often** with descriptive commit messages (see CLAUDE.md for format).
> - **Do NOT push.** Do NOT create PRs. Work stays local.
> - When a feature is done, create the **next feature branch from the current one** — branches build on top of each other sequentially.
> - **Never commit multiple unrelated features into the same branch.**
>
> ### Summary
> ```
> Branch → Plan → Analysis → TDD → Implement → Update docs → E2E tests → Verify → Done
> ```
> Skip any step and the feature is rejected.

---

> Feature proposals for upcoming Shieldoo Gate releases, ordered by impact-to-effort ratio. We prioritize features that improve real security for teams of any size over features that only matter at enterprise scale.
>
> Already-implemented features (typosquatting, version diff, maintainer risk scoring, projects, SBOM, license policy, etc.) are documented in the main [docs index](../index.md) under *Implementation Status*.

## Prioritization Criteria

Each feature is scored on two axes:

- **Security impact** — How much safer does the proxy make you? Does it catch a class of attacks nothing else catches?
- **Implementation effort** — How much code, how many new dependencies, how much infrastructure?

Features that are pure Go, need no new infrastructure, and catch attacks the current scanners miss go first. Enterprise infrastructure features (RBAC, SCIM, SIEM) are important but only relevant once you have a larger team.

## Feature Overview

### Tier 1 — Developer experience

| # | Feature | What it catches | Effort | Deps |
|---|---|---|---|---|
| 1 | [CLI & CI/CD Integration](cli-cicd-integration.md) | Nothing directly, but makes everything else *usable*. `shieldoo check`, `shieldoo audit`, GitHub Actions, pre-commit hooks. Developers finally see why their build failed. SARIF output. | Medium — separate Go binary, needs batch API endpoint | Admin API (done) |

### Tier 2 — Strong security, more effort

Cryptographic verification and software inventory. These require more integration work but are increasingly demanded by regulations (EU CRA, EO 14028).

| # | Feature | What it does | Effort | Deps |
|---|---|---|---|---|
| 2 | [Package Provenance](package-provenance.md) | Verify Sigstore/cosign signatures, npm provenance, PyPI PEP 740 attestations, NuGet/Maven signing. Catches compromised CI/CD and registry breaches. | High — per-ecosystem crypto verification, Sigstore SDK | None |
| 3 | [Dependency Graph](dependency-graph.md) | When a package is quarantined, show blast radius. "litellm is quarantined — these 14 projects depend on it." | Medium — parse dependency metadata, graph storage + UI | SBOM (done) |

**Why this order:** Provenance is the strongest defense against the LiteLLM-class attack (compromised maintainer account), but implementation is non-trivial. Dependency graph builds on the existing SBOM data and is extremely useful for incident response.

### Tier 3 — Enterprise & compliance

These matter when you have 20+ developers, auditors asking questions, or a SOC team. Smaller teams can skip or defer these.

| # | Feature | Who needs it | Effort | Deps |
|---|---|---|---|---|
| 4 | [RBAC](rbac.md) | Teams with >5 people who shouldn't all be admins. Four roles: viewer, operator, policy-approver, admin. | Medium — middleware, DB table, role mapping from OIDC claims | OIDC (done) |
| 5 | [Compliance Reporting](compliance-reporting.md) | Anyone facing SOC 2, ISO 27001, NIST SSDF, or EU CRA audits. Auto-generated evidence mapped to framework controls. | Medium — report generation, PDF/HTML export, scheduling | Audit log (done) |
| 6 | [SIEM Integration](siem-integration.md) | Teams with Splunk, Elastic, or Sentinel. Native event formatting (CIM, ECS, CEF). | Low-Medium — new alert dispatcher, per-platform formatters | Alerting (done) |
| 7 | [SCIM Provisioning](scim-provisioning.md) | Organizations with 50+ users using Entra ID, Okta, Google. Auto-sync users/groups. | High — full SCIM 2.0 server implementation | RBAC |

**Why this order:** RBAC is the minimum viable access control. Compliance reporting is increasingly non-optional even for smaller companies (EU CRA). SIEM is straightforward once alerting exists. SCIM is pure enterprise — skip until you have an IdP with hundreds of users.

> For advanced scenarios (v2.0+) — Policy-as-Code, Air-Gapped Mode, Federation, Threat Feed Contributions — see [Future Features](index-future.md).

## Dependency Graph

```
No dependencies — start any time:
  ● Package Provenance

Admin API + PAT (done)
  └──▶ CLI & CI/CD Integration

SBOM (done)
  └──▶ Dependency Graph

OIDC Auth (done)
  └──▶ RBAC
        ├──▶ SCIM Provisioning
        └──▶ SIEM Integration (recommended, not required)

Audit Log (done) + SBOM (done)
  └──▶ Compliance Reporting
```

## Implementation Notes

- **Incremental delivery:** Every feature is self-contained. Ship each one independently — no need to wait for a full tier to complete.
- **Patterns:** All features should follow existing conventions: structured JSON logging (`zerolog`), audit trail entries, Prometheus metrics, fail-open semantics where applicable, compile-time interface checks.
- **Testing:** Each feature needs unit + integration tests plus E2E coverage. Scanner features need test fixtures with known-good and known-bad samples.
