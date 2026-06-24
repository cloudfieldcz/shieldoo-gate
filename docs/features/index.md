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

> Feature roadmap for upcoming Shieldoo Gate releases, ranked by security-impact-to-effort. We prioritize controls that improve real safety for teams of any size over features that only matter at enterprise scale.
>
> **Re-baselined 2026-06-24** against the actual implementation state. This document lists only *forward-looking* work — shipped capabilities live in the main [docs index → Implementation Status](../index.md#implementation-status).

## Where Shieldoo Gate sits — the category

Shieldoo Gate is an **inline dependency firewall** (a.k.a. package firewall / artifact curation gateway): it sits on the wire between developers/CI and public registries and *prevents* a bad artifact from ever being fetched. That is a different category from the **unified AppSec / ASPM platforms** (Application Security Posture Management) — tools like Aikido, Snyk, Semgrep or GitHub Advanced Security that *observe and report* across code → cloud → runtime, usually as SaaS.

Our defensible niche is the overlap of three things almost nobody combines:

1. **Inline prevention** — block at fetch time, not a report after the fact.
2. **Self-hosted, zero data egress** — your dependency graph and source metadata never leave your network. For a *security* tool that is a feature, not a footnote.
3. **Open source (Apache 2.0)** — auditable, forkable, free for any team size.

The strategy is **not** to chase ASPM breadth (SAST, secrets, CSPM, runtime) where we would lose on feature parity. It is to be the best supply-chain firewall in existence and own the prevention lane.

### How we compare

Legend: ✓ strong / native · ◑ partial or varies by vendor · ✗ out of scope / not offered.

| Capability | **Shieldoo Gate** | Package firewalls (Socket FW, Nexus FW, JFrog Curation, Chainguard) | ASPM / AppSec platforms (Aikido, Snyk, Semgrep, GHAS) |
|---|---|---|---|
| Inline block at download (real-time prevention) | ✓ | ✓ | ✗ (scan & report) |
| Self-hosted / zero data egress | ✓ | ◑ (mostly SaaS) | ✗ (SaaS) |
| Open source | ✓ Apache 2.0 | ✗ | ✗ (mostly) |
| Multi-ecosystem proxy (7 ecosystems) | ✓ | ◑ | n/a |
| Malware detection (heuristics + AI/LLM) | ✓ | ✓ | ◑ |
| Behavioral / dynamic sandbox (gVisor) | ✓ | ◑ | ✗ |
| Typosquat & namespace-confusion detection | ✓ | ✓ | ◑ |
| Install-hook / version-diff analysis | ✓ | ◑ | ✗ |
| SCA — CVE scanning per project + rescan | ✓ | ◑ | ✓ |
| License compliance (SPDX, per-project) | ✓ | ◑ | ✓ |
| SBOM generation & export | ✓ | ✓ | ✓ |
| Package provenance / signature verification | ◑ *(roadmap T2)* | ◑ | ◑ |
| **Version cooldown / maturity gating** | ◑ *(roadmap T1 — differentiator)* | ◑ (Socket) | ✗ |
| Egress control / anti-exfiltration | ✗ *(out of scope — see [below](#considered-and-dropped--egress-control--anti-exfiltration); use network / Harden-Runner / GitHub-native firewall)* | ✗ | ✗ |
| SAST (static code analysis) | ✗ *(by design)* | ✗ | ✓ |
| Secrets scanning | ✗ *(by design)* | ✗ | ✓ |
| Cloud / IaC / CSPM / runtime protection | ✗ *(by design)* | ✗ | ✓ |

**Read of the table:** we already match or beat commercial package firewalls on the prevention lane, and we cross into SCA + license territory that usually belongs to ASPM — while staying self-hosted and open. The bold row (version cooldown) is where *nobody* in either family does it well; that's our wedge. Egress control was considered and deliberately dropped (see below) — it belongs to the network layer and is being commoditized by the CI platforms themselves.

> **Shipped capabilities are not listed here.** The canonical, always-current list lives in the [docs index → Implementation Status](../index.md#implementation-status). This roadmap stays purely forward-looking. Three items below extend partial foundations that already exist: inbound **provenance** builds on the existing outbound signing stack, the **developer CLI** extends `shdg`, and **RBAC** builds on existing auth scopes.

## Roadmap

Ordered by impact-to-effort. Each tier is independently shippable.

### Tier 1 — Cheap, high-impact prevention (do first)

| # | Feature | What it catches | Effort | Deps |
|---|---|---|---|---|
| 1 | [Version Cooldown / Maturity Gating](version-cooldown.md) **(new)** | Refuse versions younger than N days. The single cheapest control against zero-day worms — Shai-Hulud-class releases are caught and yanked within hours, so a 24–72 h cooldown blocks them with no detection logic at all. Pure Go, per-ecosystem + per-project policy. | **Low** — registry publish-time lookup + policy knob | Policy engine (done) |
| 2 | [Developer CLI & CI/CD UX](cli-cicd-integration.md) | Makes everything *usable*: `shieldoo check/audit/inspect`, override requests, SARIF, GitHub Actions, pre-commit. Today `shdg` only does CI vuln-gating. | Medium — extend `shdg`, batch API endpoint | Admin API, `shdg` (done) |

### Tier 2 — Strong cryptographic & inventory controls

| # | Feature | What it does | Effort | Deps |
|---|---|---|---|---|
| 3 | [Package Provenance (inbound)](package-provenance.md) | Verify Sigstore/cosign, npm provenance, PyPI PEP 740, NuGet/Maven signing on *fetched* packages. Verify-if-available by default, strict mode optional. Reuses our existing outbound Sigstore stack. | High — per-ecosystem crypto, Sigstore SDK | None (outbound signing done) |
| 4 | [Dependency Graph / blast radius](dependency-graph.md) | "litellm is quarantined — these 14 projects depend on it." Incident-response superpower built on existing SBOM data. | Medium — parse dep metadata, graph storage + UI | SBOM (done) |

### Tier 3 — Visibility, compliance, access (team-scale)

| # | Feature | Who needs it | Effort | Deps |
|---|---|---|---|---|
| 5 | [Compliance Reporting](compliance-reporting.md) | SOC 2 / ISO 27001 / NIST SSDF / EU CRA audits. Evidence auto-mapped to controls. Increasingly non-optional even for small EU teams. | Medium | Audit log, SBOM (done) |
| 6 | [SIEM Integration](siem-integration.md) | Splunk / Elastic / Sentinel shops. Native CIM/ECS/CEF formatting. Cheap once alerting exists. | Low-Medium | Alerting (done) |
| 7 | [RBAC](rbac.md) | Teams >5 who shouldn't all be admins. Four roles: viewer / operator / policy-approver / admin. Auth scopes already exist as the primitive. | Medium | OIDC, auth scopes (done) |

### Considered and dropped — Egress control / anti-exfiltration

We evaluated an egress (anti-exfiltration) companion that would block what *leaves* CI/build/prod, to cover the exfiltration phase of a supply-chain attack. **Decision: not building it.** Enforcing egress belongs to the network layer, not to a package proxy, and the space is already well served: existing network controls (hub-spoke firewall, k8s NetworkPolicy / service mesh) cover self-hosted infra; **StepSecurity Harden-Runner** covers GitHub Actions today; and **GitHub is shipping a native egress firewall** for hosted runners that runs *outside* the runner VM (immutable even with root inside) — architecturally a place Shieldoo Gate cannot reach. Competing here would mean entering a crowded space about to be commoditized by the platform owner. Shieldoo Gate stays focused on the **ingress** lane (proxy-scan-and-block at fetch), which none of those tools do, and at most documents how to pair it with a runner egress firewall.

> Advanced v2.0+ scenarios — [SCIM Provisioning](scim-provisioning.md) (rides on RBAC), [Policy-as-Code (OPA)](policy-as-code.md), [Air-Gapped Mode](air-gapped-mode.md), [Threat-Feed Contributions](threat-feed-contributions.md) — live in [Future Features](index-future.md). (Multi-Instance Federation was dropped.)

## Suggested sequence

```
Now (weeks)           Next (this quarter)        Later (next quarter+)
─────────────         ───────────────────        ─────────────────────
1 Version Cooldown ──▶ 3 Package Provenance ──▶  5 Compliance Reporting
2 Developer CLI    ──▶ 4 Dependency Graph    ──▶  6 SIEM · 7 RBAC
                                              ──▶  v2.0: SCIM / OPA / air-gap / threat-feed portal
```

Rationale: Tier 1 is days-to-weeks of pure-Go work that immediately raises the security floor (cooldown) and the daily UX (CLI). Provenance and the dependency graph are the highest-value "real" features and both reuse infrastructure that already exists. Tier 3 is team-scale visibility and access — pull forward whichever an actual audit or headcount demands.

## Per-feature quick analysis

Lightweight starting point for "analyze-then-implement, one piece at a time". Each card: the smallest shippable slice, main risk, and rough size. Full design lives in the linked feature doc.

**1 · Version Cooldown** *(new — [doc](version-cooldown.md))*
First slice: a global `min_age` default, **resolved and overridable per project** (same unit as license policy — a project can run a stricter cooldown or relax it for a justified urgent upgrade), enforced in the policy engine using the registry's publish timestamp; block + clear verdict reason when too new. Risk: clock/timestamp sourcing differs per ecosystem; needs a per-registry "published-at" resolver. Size: S. Highest ROI on the board.

**2 · Developer CLI & CI/CD UX** *([doc](cli-cicd-integration.md))*
First slice: `shieldoo check <ecosystem:pkg:ver>` hitting a new read-only batch endpoint; SARIF output next. Risk: scope creep vs `shdg` — decide whether to extend `shdg` or ship a second binary (recommend extend). Size: M.

**3 · Package Provenance (inbound)** *([doc](package-provenance.md))*
First slice: npm provenance + PyPI PEP 740 in verify-if-available mode (highest adoption, JSON-based, no exotic crypto). Sigstore/cosign for OCI next, reusing our outbound Fulcio/Rekor code. Risk: false-block if "strict" is enabled before ecosystem coverage is real — ship advisory-only first. Size: M per ecosystem.

**4 · Dependency Graph** *([doc](dependency-graph.md))*
First slice: extract direct deps at scan time into one new table + `GET /artifacts/{id}/dependents`. UI graph later. Risk: version-constraint resolution is fuzzy — store raw constraints, don't over-engineer resolution. Size: M.

**5 · Compliance Reporting** — First slice: one report type (Executive Summary) as HTML from existing audit data; framework mappings next. Size: M.

**6 · SIEM** — First slice: generic CEF-over-syslog dispatcher reusing the alerting interface; per-platform formatters next. Size: S–M.

**7 · RBAC** — Full four-role model (viewer / operator / policy-approver / admin) mapped from OIDC group claims onto the existing auth scopes. First slice can wire the roles end-to-end against the permission matrix in the [RBAC doc](rbac.md); ship all four rather than a reduced set. Size: M.

*(SCIM, OPA, Air-Gapped, Threat-Feed portal → [Future Features](index-future.md).)*

## Implementation notes

- **Incremental delivery:** every feature is self-contained — ship independently, no need to wait for a full tier.
- **Patterns:** follow existing conventions — structured `zerolog` JSON logging, audit-trail entries, Prometheus metrics, fail-open vs fail-closed per [ADR-012](../adr/ADR-012-fail-closed-scanner-errors.md), compile-time interface checks.
- **Testing:** unit + integration + E2E for each feature; scanner/policy features need known-good and known-bad fixtures.
- **Workflow:** see the *Instructions for Ralph* block at the top of this file — Branch → Plan → Analysis → TDD → Implement → Docs → E2E → Verify.
