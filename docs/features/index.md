# Planned Features

> Feature proposals for future Shieldoo Gate releases, ordered by impact-to-effort ratio. We prioritize features that improve real security for teams of any size over features that only matter at enterprise scale.

## Prioritization Criteria

Each feature is scored on two axes:

- **Security impact** — How much safer does the proxy make you? Does it catch a class of attacks nothing else catches?
- **Implementation effort** — How much code, how many new dependencies, how much infrastructure?

Features that are pure Go, need no new infrastructure, and catch attacks the current scanners miss go first. Enterprise infrastructure features (RBAC, SCIM, SIEM) are important but only relevant once you have a larger team.

## Feature Overview

### Tier 1 — Maximum bang for the buck (v1.2)

Pure detection improvements. No new infrastructure. Each one catches an attack class that content scanners fundamentally cannot. All can be built independently and in parallel.

| # | Feature | What it catches | Effort | Deps |
|---|---|---|---|---|
| 1 | [Typosquatting Detection](typosquatting-detection.md) | Fake packages impersonating popular libraries (`reqeusts`, `lodsah`). Edit distance, homoglyph, namespace confusion analysis. | Low — built-in scanner, pure Go, <1ms per check | None |
| 2 | [Version Diff Analysis](version-diff-analysis.md) | Compromised updates — compare new version against cached previous version. Anomalous code additions, new install hooks, entropy spikes. | Medium — needs archive extraction + diff logic, async | Cache (done) |
| 3 | [Maintainer Risk Scoring](maintainer-risk-scoring.md) | Account takeovers, abandoned package hijacking, ownership transfers. Scores packages by maintainer history + publication patterns. | Medium — upstream API queries, caching | None |
| 4 | [CLI & CI/CD Integration](cli-cicd-integration.md) | Nothing directly, but makes everything else *usable*. `shieldoo check`, `shieldoo audit`, GitHub Actions, pre-commit hooks. Developers finally see why their build failed. SARIF output. | Medium — separate Go binary, needs batch API endpoint | Admin API (done) |

**Why this order:** Typosquatting is the cheapest scanner to build and catches the most common attack vector. Version diff is the most powerful signal against account-takeover attacks. Maintainer scoring adds context that amplifies every other scanner. CLI makes the whole system usable for developers instead of just admins.

### Tier 2 — Strong security, more effort (v1.3)

Cryptographic verification, license compliance, and software inventory. These require more integration work but are increasingly demanded by regulations (EU CRA, EO 14028).

| # | Feature | What it does | Effort | Deps |
|---|---|---|---|---|
| 5 | [Package Provenance](package-provenance.md) | Verify Sigstore/cosign signatures, npm provenance, PyPI PEP 740 attestations, NuGet/Maven signing. Catches compromised CI/CD and registry breaches. | High — per-ecosystem crypto verification, Sigstore SDK | None |
| 6 | [SBOM Generation](sbom-generation.md) | Auto-generate CycloneDX / SPDX for every artifact. Trivy already supports it — mostly wiring. | Low-Medium — Trivy does the heavy lifting | Trivy (done) |
| 7 | [License Policy](license-policy.md) | Block GPL/AGPL in commercial projects, warn on unknown licenses. Prevents legal headaches. | Low — parse SPDX identifiers from SBOM, config-driven rules | SBOM (recommended) |
| 8 | [Dependency Graph](dependency-graph.md) | When a package is quarantined, show blast radius. "litellm is quarantined — these 14 projects depend on it." | Medium — parse dependency metadata, graph storage + UI | SBOM (recommended) |

**Why this order:** Provenance is the strongest defense against the LiteLLM-class attack (compromised maintainer account), but implementation is non-trivial. SBOM is almost free thanks to Trivy and unlocks the next two features. License policy is simple once you have SBOM. Dependency graph is the most complex here but extremely useful for incident response.

### Tier 3 — Enterprise & compliance (v1.4)

These matter when you have 20+ developers, auditors asking questions, or a SOC team. Smaller teams can skip or defer these.

| # | Feature | Who needs it | Effort | Deps |
|---|---|---|---|---|
| 9 | [RBAC](rbac.md) | Teams with >5 people who shouldn't all be admins. Four roles: viewer, operator, policy-approver, admin. | Medium — middleware, DB table, role mapping from OIDC claims | OIDC (done) |
| 10 | [Compliance Reporting](compliance-reporting.md) | Anyone facing SOC 2, ISO 27001, NIST SSDF, or EU CRA audits. Auto-generated evidence mapped to framework controls. | Medium — report generation, PDF/HTML export, scheduling | Audit log (done) |
| 11 | [SIEM Integration](siem-integration.md) | Teams with Splunk, Elastic, or Sentinel. Native event formatting (CIM, ECS, CEF). | Low-Medium — new alert dispatcher, per-platform formatters | Alerting (done) |
| 12 | [SCIM Provisioning](scim-provisioning.md) | Organizations with 50+ users using Entra ID, Okta, Google. Auto-sync users/groups. | High — full SCIM 2.0 server implementation | RBAC |

**Why this order:** RBAC is the minimum viable access control. Compliance reporting is increasingly non-optional even for smaller companies (EU CRA). SIEM is straightforward once alerting exists. SCIM is pure enterprise — skip until you have an IdP with hundreds of users.

### Tier 4 — Advanced scenarios (v2.0+)

Specialized deployment models. Only implement when there's concrete demand.

| # | Feature | Use case | Effort | Deps |
|---|---|---|---|---|
| 13 | [Policy-as-Code (OPA)](policy-as-code.md) | Complex conditional policies ("block suspicious in prod, allow in dev"). Rego rules in Git, testable, dry-run mode. | Medium-High — embedded OPA, policy loading, decision logging | Policy engine (done) |
| 14 | [Air-Gapped Mode](air-gapped-mode.md) | Defense, government, critical infrastructure. Signed export bundles, local vuln DB, curated repo mode. | High — export/import mechanism, bundle signing, offline scanners | Cache (done) |
| 15 | [Multi-Instance Federation](multi-instance-federation.md) | Multi-region, multi-team, hybrid cloud. Share threat detections across instances via mTLS. | High — sync protocol, conflict resolution, peer management | None |
| 16 | [Threat Feed Contributions](threat-feed-contributions.md) | Community threat sharing portal. Separate service with moderation workflow. | High — separate service, review process, GPG-signed feed | Threat feed (done) |

## Priority Matrix

```
                        High security impact
                              │
       Typosquatting ●        │         ● Version Diff
                              │
    Maintainer Risk ●         │       ● Package Provenance
                              │
              CLI ●           │     ● SBOM
                              │
         License ●            │  ● Dep Graph
                              │
Low effort ───────────────────┼──────────────────── High effort
                              │
          SIEM ●              │    ● RBAC
                              │
  Compliance Reporting ●      │         ● OPA Policy
                              │
                              │     ● SCIM
                              │
                              │           ● Air-Gap
                              │
                              │            ● Federation
                              │
                        Low security impact
                       (but high operational value)
```

## Dependency Graph

```
No dependencies — start any time:
  ● Typosquatting Detection
  ● Maintainer Risk Scoring
  ● Package Provenance
  ● Multi-Instance Federation

Cache (done)
  ├──▶ Version Diff Analysis
  └──▶ Air-Gapped Mode

Admin API + PAT (done)
  └──▶ CLI & CI/CD Integration

Trivy (done)
  └──▶ SBOM Generation
        ├──▶ License Policy
        └──▶ Dependency Graph

OIDC Auth (done)
  └──▶ RBAC
        ├──▶ SCIM Provisioning
        └──▶ SIEM Integration (recommended, not required)

Audit Log (done) + SBOM (recommended)
  └──▶ Compliance Reporting

Policy Engine (done)
  └──▶ Policy-as-Code (OPA)

Threat Feed (done)
  └──▶ Threat Feed Contributions (separate service)
```

## Implementation Notes

- **Parallelism:** Tier 1 features have no mutual dependencies. All four can be developed simultaneously by different contributors.
- **Quick wins:** Typosquatting detection and SBOM generation are the lowest-effort features with immediate value. Good candidates for a first community contribution.
- **Incremental delivery:** Every feature is self-contained. Ship each one independently — no need to wait for a full tier to complete.
- **Patterns:** All features should follow existing conventions: structured JSON logging (`zerolog`), audit trail entries, Prometheus metrics, fail-open semantics where applicable, compile-time interface checks.
- **Testing:** Each feature needs unit + integration tests. Scanner features need test fixtures with known-good and known-bad samples.
