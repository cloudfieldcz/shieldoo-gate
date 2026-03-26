# Shieldoo Gate v1.0 Core — Plan Index

**Source:** [`docs/plans/2026-03-25-v1-core.md`](./2026-03-25-v1-core.md) (design + analysis)

**Created:** 2026-03-26

## Phases

| # | Phase | Plan File | Status | Dependencies |
|---|-------|-----------|--------|--------------|
| 1 | Project Skeleton + Config + DB + Models | [plan-1-skeleton.md](./2026-03-25-v1-core-plan-1-skeleton.md) | ⬚ Not started | — |
| 2 | Scanner Engine + Built-in Scanners | [plan-2-scanner-engine.md](./2026-03-25-v1-core-plan-2-scanner-engine.md) | ⬚ Not started | Phase 1 |
| 3 | External Scanners (GuardDog, Trivy, OSV) | [plan-3-external-scanners.md](./2026-03-25-v1-core-plan-3-external-scanners.md) | ⬚ Not started | Phase 2 |
| 4 | Cache Store + Policy Engine + Threat Feed | [plan-4-cache-policy.md](./2026-03-25-v1-core-plan-4-cache-policy.md) | ⬚ Not started | Phase 1 |
| 5 | Protocol Adapters (PyPI, npm, Docker, NuGet) | [plan-5-adapters.md](./2026-03-25-v1-core-plan-5-adapters.md) | ⬚ Not started | Phases 2, 3, 4 |
| 6 | REST API + Prometheus Metrics | [plan-6-api.md](./2026-03-25-v1-core-plan-6-api.md) | ⬚ Not started | Phases 1–5 |
| 7 | Admin UI (React) | [plan-7-ui.md](./2026-03-25-v1-core-plan-7-ui.md) | ⬚ Not started | Phase 6 |
| 8 | Main Entrypoint + Docker Compose + E2E | [plan-8-integration.md](./2026-03-25-v1-core-plan-8-integration.md) | ⬚ Not started | All previous |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Dependency Graph

```
Phase 1 (Skeleton)
  ├──► Phase 2 (Scanner Engine) ──► Phase 3 (External Scanners) ──┐
  └──► Phase 4 (Cache + Policy) ──────────────────────────────────┤
                                                                   ▼
                                                      Phase 5 (Adapters)
                                                           │
                                                           ▼
                                                      Phase 6 (REST API)
                                                           │
                                                           ▼
                                                      Phase 7 (Admin UI)
                                                           │
                                                           ▼
                                                      Phase 8 (Integration + E2E)
```

## Notes

- Phases 2 and 4 have no dependency between them — they can be executed in parallel
- Phase 3 depends only on Phase 2 — can run in parallel with Phase 4
- Each phase plan is self-contained and can be executed independently via `cf-powers:subagent-driven-development` or `cf-powers:executing-plans`
- All code follows conventions in [`CLAUDE.md`](../../CLAUDE.md) and interfaces from [`docs/initial-analyse.md`](../initial-analyse.md)
