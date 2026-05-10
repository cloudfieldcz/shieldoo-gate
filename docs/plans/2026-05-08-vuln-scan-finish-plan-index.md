# Vulnerability Scan — Final Polish — Plan Index

**Source:** [`docs/plans/2026-05-07-vulnerability-scan/IMPLEMENTATION_STATUS.md`](2026-05-07-vulnerability-scan/IMPLEMENTATION_STATUS.md) "Cross-cutting / not-yet-tackled" + Phase 8 follow-ups.

**Created:** 2026-05-08

## Goal

Close the four follow-up gaps that IMPLEMENTATION_STATUS calls out as 🟡/❌, plus one architectural correction the user flagged in 2026-05-08 review:

1. **`shdg` CLI** (`cmd/shdg/`) — `scan` + `version` subcommands; bundles a pinned Trivy at first run; default async with optional `--wait` + `--fail-on critical|high|none` for CI gates.
2. **Per-ecosystem E2E shell tests** — pypi/npm/docker fixtures that round-trip through the upload + scan pipeline.
3. **Security E2E shell tests** — panic-redaction (no Authorization in stack traces), super-token-audit (`super_token_used` row emitted on both auth paths), AI bridge SSRF smoke (adversarial `repo_url` does not crash the bridge or leak).
4. **`shdg` E2E shell test** — built binary uploads a real SBOM through the test rig and (with `--wait`) polls to a terminal status; CI-style smoke test of the CLI itself.
5. **Playwright UI E2E** — XSS guard (SBOM-borne `<script>` payloads do not fire `alert`) + happy-path lifecycle (upload → ignore → revoke through the UI).
6. **License-override per-project scoping** — license-blocked artifacts must be released **per project** (matching the per-project license-policy model), not via the global `policy_overrides` table. The Release flow moves to Project Detail; existing globals are backfilled into per-project rows.

Everything else in the plan ships green; this is the merge-blocker cleanup pass.

## Phases

| # | Phase | Plan File | Status | Dependencies |
|---|-------|-----------|--------|--------------|
| 1 | `shdg` CLI core (scaffold, ecosystem detection, Trivy bundling, upload) | [plan-1-cli-core.md](./2026-05-08-vuln-scan-finish-plan-1-cli-core.md) | ✅ Complete | — |
| 2 | `shdg` `--wait` + `--fail-on` polling | [plan-2-cli-wait.md](./2026-05-08-vuln-scan-finish-plan-2-cli-wait.md) | ✅ Complete | Phase 1 |
| 3 | E2E shell test suite (pypi/npm/docker + panic + super-token + ssrf + **shdg smoke**) | [plan-3-e2e-shell.md](./2026-05-08-vuln-scan-finish-plan-3-e2e-shell.md) | ✅ Complete | Phases 1+2 (for shdg smoke test only) |
| 4 | Playwright UI E2E (XSS + happy-path) | [plan-4-e2e-playwright.md](./2026-05-08-vuln-scan-finish-plan-4-e2e-playwright.md) | ✅ Complete | — |
| 5 | License-override per-project scoping (backend + UI + migration) | [plan-5-license-overrides.md](./2026-05-08-vuln-scan-finish-plan-5-license-overrides.md) | ✅ Complete | — |
| 6 | Documentation + IMPLEMENTATION_STATUS update | [plan-6-docs.md](./2026-05-08-vuln-scan-finish-plan-6-docs.md) | ✅ Complete | Phases 1–5 |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Notes

- Phases 1+2 are sequential (the wait flag depends on the scaffold).
- Phases 3 and 4 are independent of the CLI — they exercise the existing API/UI surfaces — and can run in parallel with Phase 1+2.
- **Phase 5 (license-override scoping) is independent of the rest** — it touches a different surface (license policy + project detail). Can run in parallel with the CLI work, but its UI changes are best validated through the Phase 4 Playwright suite, so consider sequencing 4 → 5 if browser tests need to assert the new license-overrides panel.
- Phase 6 (docs) is sequenced last so it can reference the actual final shape of CLI flags, test layout, and license-overrides API.
- Verification gate per phase: `go build ./... && go test ./... && cd ui && npm run build` must stay green; `make test-e2e-containerized` is the merge gate (re-run before final commit).
- All CLI dependencies must be pinned per [CLAUDE.md](../../CLAUDE.md#version-pinning--mandatory). Trivy is pinned to **v0.70.0** (see `cmd/shdg/trivy.go:41`).
- `shdg` uses **Go stdlib only** (`flag.NewFlagSet`, `net/http`) — no cobra, urfave/cli — matching the rest of the repo.
