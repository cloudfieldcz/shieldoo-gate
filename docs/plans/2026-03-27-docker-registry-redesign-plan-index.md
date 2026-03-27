# Docker Registry Redesign — Plan Index

**Source:** [`2026-03-27-docker-registry-redesign.md`](./2026-03-27-docker-registry-redesign.md) (design + analysis)

**Created:** 2026-03-27

## Phases

| # | Phase | Plan File | Status | Dependencies |
|---|-------|-----------|--------|--------------|
| 1 | Multi-Upstream Routing + Allowlist | [plan-1-multi-upstream.md](./2026-03-27-docker-registry-redesign-plan-1-multi-upstream.md) | ✅ Complete | — |
| 2 | Push Support | [plan-2-push.md](./2026-03-27-docker-registry-redesign-plan-2-push.md) | ✅ Complete | Phase 1 |
| 3 | Scheduled Sync | [plan-3-sync.md](./2026-03-27-docker-registry-redesign-plan-3-sync.md) | ✅ Complete | Phase 1 |
| 4a | Tag Management API | [plan-4a-tag-api.md](./2026-03-27-docker-registry-redesign-plan-4a-tag-api.md) | ✅ Complete | Phase 1, 2 |
| 4b | Tag Management UI | [plan-4b-tag-ui.md](./2026-03-27-docker-registry-redesign-plan-4b-tag-ui.md) | ✅ Complete | Phase 3, 4a |
| 5 | E2E Tests | [plan-5-e2e.md](./2026-03-27-docker-registry-redesign-plan-5-e2e.md) | ✅ Complete | Phase 1-4a |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Notes

- Phase 2 (Push) and Phase 3 (Sync) can be executed in parallel — both depend only on Phase 1
- Each phase plan is self-contained and can be executed independently via executing-plans or subagent-driven-development
- Phase 4b (UI) is the only phase requiring all others to be complete
- Phase 5 (E2E) tests all features end-to-end — run after Phases 1-4a are implemented
