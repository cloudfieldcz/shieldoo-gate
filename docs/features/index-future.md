# Future Features (v2.0+)

> Advanced scenarios and specialized deployment models. Only implement when there's concrete demand. For current planned features (Tiers 1–3), see [Planned Features](index.md).

## Tier 4 — Advanced scenarios

| # | Feature | Use case | Effort | Deps |
|---|---|---|---|---|
| 13 | [Policy-as-Code (OPA)](policy-as-code.md) | Complex conditional policies ("block suspicious in prod, allow in dev"). Rego rules in Git, testable, dry-run mode. | Medium-High — embedded OPA, policy loading, decision logging | Policy engine (done) |
| 14 | [Air-Gapped Mode](air-gapped-mode.md) | Defense, government, critical infrastructure. Signed export bundles, local vuln DB, curated repo mode. | High — export/import mechanism, bundle signing, offline scanners | Cache (done) |
| 15 | [Multi-Instance Federation](multi-instance-federation.md) | Multi-region, multi-team, hybrid cloud. Share threat detections across instances via mTLS. | High — sync protocol, conflict resolution, peer management | None |
| 16 | [Threat Feed Contributions](threat-feed-contributions.md) | Community threat sharing portal. Separate service with moderation workflow. | High — separate service, review process, GPG-signed feed | Threat feed (done) |

## Dependency Graph

```
No dependencies — start any time:
  ● Multi-Instance Federation

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
