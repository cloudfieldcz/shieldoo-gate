# SHA256 Integrity Gate — Plan Index

**Source:** Security audit conversation 2026-04-10 (no separate analysis doc)

**Created:** 2026-04-10

## Problem Statement

Critical security gap: the proxy has no SHA256 integrity verification between what was scanned and what is served from cache. Additionally:
- Tag mutability detection compares incompatible hash formats (SHA256 hex vs SHA512 SRI / ETag) — always false-positive
- Policy overrides do not pin content hash — an override for `npm:foo:1.0.0` approves ANY content at that version
- Rescan scheduler does not verify cached file integrity before re-scanning
- No way to delete an artifact (cache + DB) — the only resolution for integrity mismatch

## Design Decisions

1. **SHA256 verification is fail-closed** — if we cannot verify, we do NOT serve
2. **Integrity mismatch = SECURITY INCIDENT** — quarantine + alert + audit log with dedicated event type `INTEGRITY_VIOLATION`
3. **Delete artifact** is the only resolution for integrity mismatch — purges cache + DB, next request re-fetches fresh
4. **Local cache Get() must verify SHA256** — cloud backends (S3, Azure, GCS) already do this; local does not
5. **Tag mutability uses SHA256 consistently** — store upstream SHA256 in `tag_digest_history`, not ETag/SRI

## Production State (2026-04-10)

- 2013 artifacts (953 npm, 531 nuget, 408 pypi, 117 go, 4 docker)
- 2005 CLEAN, 7 QUARANTINED, 1 PENDING_SCAN
- 38 active policy overrides (all version-scoped)
- `tag_digest_history` is empty (mutability check never worked correctly)
- SHA256 values in `artifacts` table are correct 64-char hex strings — no data migration needed

## Phases

| # | Phase | Plan File | Status | Dependencies |
|---|-------|-----------|--------|--------------|
| 1 | Integrity verification core | [plan-1-integrity-core.md](./2026-04-10-sha256-integrity-gate-plan-1-integrity-core.md) | ⬚ Not started | — |
| 2 | Delete artifact API + E2E tests | [plan-2-delete-artifact.md](./2026-04-10-sha256-integrity-gate-plan-2-delete-artifact.md) | ⬚ Not started | Phase 1 |
| 3 | Fix tag mutability | [plan-3-fix-mutability.md](./2026-04-10-sha256-integrity-gate-plan-3-fix-mutability.md) | ⬚ Not started | Phase 1 |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Notes

- Phase 2 and 3 can run in parallel (both depend only on Phase 1)
- No DB schema migration required — existing `artifacts.sha256` data is correct
- New event type `INTEGRITY_VIOLATION` needs to be added to `model/audit.go`
- Production deployment: phases are independently deployable after Phase 1
- E2E integrity tests run only in PostgreSQL passes (Run 2/3), skipped in SQLite (Run 1)
- After Phase 1, policy overrides cannot bypass integrity — every cache serve verifies SHA256
- Rescan scheduler verifies cache integrity before scanning (Phase 1, Task 6)
