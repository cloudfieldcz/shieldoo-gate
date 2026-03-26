# Policy Overrides (False-Positive Management) — Plan Index

**Source:** Conversation-driven design — dynamic allowlist managed via UI/API

**Created:** 2026-03-26

## Summary

When a scanner produces a false positive (e.g., `requests` flagged as malicious), users need a way to mark the artifact as safe directly from the UI. This creates a "policy override" stored in the database that takes precedence over scanner verdicts. Overrides can target a specific version or an entire package.

## Phases

| # | Phase | Plan File | Status | Dependencies |
|---|-------|-----------|--------|--------------|
| 1 | Backend: DB + Model + Policy Engine + API | [plan-1-backend.md](./2026-03-26-policy-overrides-plan-1-backend.md) | ✅ Complete | — |
| 2 | Frontend: UI components + Overrides page | [plan-2-frontend.md](./2026-03-26-policy-overrides-plan-2-frontend.md) | ✅ Complete | Phase 1 |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Architecture

```
UI: Artifact detail → "Mark as False Positive" button
     │                              │
     ▼                              ▼
API: POST /api/v1/overrides    POST /api/v1/artifacts/{id}/override
     │
     ▼
DB: policy_overrides table
     │
     ▼
Policy Engine: Evaluate() checks DB overrides FIRST, then static allowlist, then rules
```

## Key Design Decisions

1. **Overrides live in DB, not config** — allows runtime management without restart
2. **Policy engine gets DB access** — override check happens inside Evaluate(), keeping all policy logic centralized
3. **Two scope modes**: `version` (exact match, safer) and `package` (all versions, convenient)
4. **Override + release in one action** — when overriding a quarantined artifact, status is automatically set to CLEAN
5. **Audit trail** — every override create/revoke is logged in audit_log

## Notes

- Phase 2 depends on Phase 1 (API must exist before UI can call it)
- Each phase is self-contained and can be executed independently
