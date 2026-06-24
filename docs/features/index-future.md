# Future Features (v2.0+)

> Advanced scenarios and specialized deployment models. Only implement when there's concrete demand. For current planned features (Tiers 1–3), see [Planned Features](index.md). Numbering continues from that roadmap (which ends at #7).

## Tier 4 — Advanced scenarios

| # | Feature | Use case | Effort | Deps |
|---|---|---|---|---|
| 8 | [SCIM Provisioning](scim-provisioning.md) | Auto-sync users/groups from an IdP (Entra/Okta/Google) once [RBAC](rbac.md) exists. Pure enterprise — only worth it at 50+ users with a real IdP. | High — full SCIM 2.0 server | RBAC |
| 9 | [Policy-as-Code (OPA)](policy-as-code.md) | Complex conditional policies ("block suspicious in prod, allow in dev"; "quarantine a too-new version only if it *also* has install hooks"). Rego rules in Git, testable, dry-run mode. Natural home for composing cooldown + provenance signals. **Revisit vs. simpler built-in conditional rules before committing** — risk of over-engineering. | Medium-High — embedded OPA, policy loading, decision logging | Policy engine (done) |
| 10 | [Air-Gapped Mode](air-gapped-mode.md) | Defense, government, critical infrastructure, regulated EU. Signed export bundles, local vuln DB, curated repo mode. | High — export/import mechanism, bundle signing, offline scanners | Cache (done) |
| 11 | [Threat Feed Contributions](threat-feed-contributions.md) | Community threat sharing — fits the Apache-2.0 community mission. **Start minimal** (GitHub issue → OSV-format PR workflow) rather than building a full moderated portal; grow into the portal only once there's real submission volume. | High (portal) / Low (minimal workflow) | Threat feed (done) |

> **Dropped:** *Multi-Instance Federation* (cross-instance threat sync via mTLS) — too much machinery (sync protocol, conflict resolution, peer management) for the benefit; the shared threat feed already covers ~80% of the need.

## Dependency Graph

```
RBAC (planned, Tier 3)
  └──▶ SCIM Provisioning

Cache (done)
  └──▶ Air-Gapped Mode

Policy Engine (done)
  └──▶ Policy-as-Code (OPA)

Threat Feed (done)
  └──▶ Threat Feed Contributions (separate service)
```

## Implementation Notes

- These features are **not prioritized** for v1.x releases.
- Each feature is self-contained and can be implemented independently.
- **Patterns:** All features should follow existing conventions: structured JSON logging (`zerolog`), audit trail entries, Prometheus metrics, fail-open semantics where applicable, compile-time interface checks.
- **Testing:** Each feature needs unit + integration tests.
