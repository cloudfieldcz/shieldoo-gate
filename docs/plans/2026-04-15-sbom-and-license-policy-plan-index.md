# SBOM + License Policy + Project Registry — Plan Index

**Source:** [2026-04-15-sbom-and-license-policy.md](./2026-04-15-sbom-and-license-policy.md) (design + analysis v1.1)

**Created:** 2026-04-15

## Phases

| # | Phase | Status | Dependencies |
|---|-------|--------|--------------|
| 1 | Project Registry + Auth Integration | 🔨 In progress | — |
| 2 | SBOM Generation (Trivy single-run, blob storage, API) | ⬚ Not started | Phase 1 (optional, can parallelize) |
| 3 | License Policy (evaluator, engine integration, API) | ⬚ Not started | Phase 1 + Phase 2 |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Execution Notes

- User directive: **pracuj samostatne** — proceed autonomously through all phases.
- Detailed tasks are inlined from the analysis document above (sections "Implementační fáze" + "Dotčené soubory").
- Each phase ends with E2E tests in `tests/e2e-shell/` and docs updates.
- Final verification: `make test-e2e-containerized` (3 runs: strict+SQLite+local / balanced+PG+S3 / permissive+AzBlob) must be green.
