---
status: REVIEWED — v2 incorporates BA + Dev + Security + Perf cross-check feedback
type: technical-analysis
date: 2026-05-02
related:
  - docs/features/typosquatting-detection.md
  - docs/scanners.md
  - docs/policy.md
  - docs/api/openapi.yaml
---

# Typosquat pre-scan rollout — extend override flow to NuGet, Maven, RubyGems, gomod, Docker

## Overview

The typosquat pre-scan + override flow shipped in commit `7b77235` (`feat(typosquat): make typosquat blocks overridable from the artifacts pane`) is wired only into the **npm** and **PyPI** adapters. The underlying `builtin-typosquat` scanner already supports all 7 ecosystems and is seeded with popular packages for each (PyPI 159, npm 188, RubyGems 90, NuGet 78, Docker 40, Maven 76, Go 82). What is missing is the per-adapter integration — the call to `Engine.PreScanTyposquat()`, the `policyEngine.HasOverride()` short-circuit, the `adapter.PersistTyposquatBlock()` write, and the synthetic-artifact behaviour that lets admins Release the block from the Artifacts pane.

This analysis plans the rollout of that pattern to the remaining 5 adapters: **NuGet**, **Maven**, **RubyGems**, **gomod**, **Docker**, plus a set of pre-rollout fixes uncovered by cross-check review (Phase 0).

### Why

- **Parity.** Operators already see typosquat blocks for npm and PyPI. The same UX should apply to every ecosystem the proxy supports.
- **Defense in depth.** The current state silently lets typosquat names through to upstream for NuGet/Maven/RubyGems/gomod/Docker — the post-download scan only catches malicious *content*, not malicious *naming*. The pre-scan gate prevents the proxy from confirming "this typosquat name exists upstream" by issuing a fetch.
- **Existing latent bug uncovered.** Cross-check review found that the current PyPI typosquat Release flow is **broken** because `PersistTyposquatBlock` writes `sha256=""` and the next legitimate fetch trips `VerifyUpstreamIntegrity`'s SHA-mismatch check, auto-quarantining the artifact. Phase 0 fixes this for the existing PyPI case before extending the pattern.
- **No new scanner work.** The `builtin-typosquat` scanner already declares support for all 7 ecosystems (`internal/scanner/builtin/typosquat.go:93-103`) and the seed table already has popular-package coverage in each. This is purely an adapter-integration project plus the bugfix and supporting infrastructure.

## Current state

### Reference implementation: npm

`internal/adapter/npm/npm.go` exposes a private helper, `blockIfTyposquat(w, r, pkgName, version)`, called from 5 routes (lines 138, 152, 179, 198, 288):

- `handlePackageMetadata` and `handleScopedPackageMetadata` — name-only (version="").
- `handleVersionMetadata` and `handleScopedVersionMetadata` — version-scoped.
- `handleTarballDownload` — version-scoped, version derived from the tarball filename.

The helper itself (`internal/adapter/npm/npm.go:632-701`):

1. Calls `a.scanEngine.PreScanTyposquat(ctx, pkgName, EcosystemNPM)`. Returns false (no block) on `CLEAN` verdict or scanner-not-registered.
2. Sanitizes the package name (`/` → `_`, `@` removed) and substitutes `adapter.TyposquatPlaceholderVersion` (`"*"`) for empty versions, then composes the canonical artifact ID.
3. Calls `policyEngine.HasOverride(ctx, EcosystemNPM, pkgName, version)`. If an override exists, writes an `EVENT_SERVED` audit entry and returns false.
4. Otherwise: logs the block, calls `adapter.PersistTyposquatBlock()`, returns 403 JSON, writes an `EVENT_BLOCKED` audit entry. Returns true.

### Reference implementation: PyPI

`internal/adapter/pypi/pypi.go:248-293` inlines the same pattern (no helper) inside `downloadScanServe`, run after the cache lookup but before the upstream download.

### Shared infrastructure (already in place, modified in Phase 0)

- `internal/scanner/engine.go:139-159` — `PreScanTyposquat(ctx, name, ecosystem)`.
- `internal/policy/engine.go:222-256` — `HasOverride(ctx, ecosystem, name, version)`. **Phase 0 changes the return type to `(int64, bool)` so the audit log can record which override let a request through.**
- `internal/adapter/base.go:545-604` — `TyposquatPlaceholderVersion = "*"`, `PersistTyposquatBlock(...)`. **Phase 0 changes this helper to always store `version="*"` for typosquat blocks (decision C: package-scope for all ecosystems), and to add an in-process LRU dedup so repeated probes don't spam `scan_results` and `audit_log`.**
- `internal/adapter/base.go:664-695` — `VerifyUpstreamIntegrity(...)`. **Phase 0 adds an `existingSHA256 == ""` short-circuit so synthetic typosquat rows do not trigger false integrity violations on the legitimate-fetch-after-Release path.**
- `internal/api/artifacts.go:553-561` — `handleReleaseArtifact` already detects `version == TyposquatPlaceholderVersion` and creates a `scope='package'` override. After Phase 0 makes all typosquat blocks package-scope, this branch handles every ecosystem uniformly.
- `ui/src/components/ArtifactDetailPanel.tsx`, `ArtifactTable.tsx` — render `*` as `(any version)`.

### Current gap per adapter

| Adapter | File / lines | Where pre-scan should hook | Block site coverage today |
|---|---|---|---|
| NuGet | `internal/adapter/nuget/nuget.go:210, 240` | `handleRegistration` (name-only), `handleNupkgDownload` (version-scoped) | Only post-download Trivy scan. |
| Maven | `internal/adapter/maven/maven.go:290` | `downloadScanServe` for scannable artifacts (`.jar`/`.war`/`.aar`/`.zip`) | Only post-download Trivy scan. |
| RubyGems | `internal/adapter/rubygems/rubygems.go:280` | `downloadScanServe` (version-scoped, name+version derived from filename) | Only post-download scan. |
| gomod | `internal/adapter/gomod/gomod.go:115-138, 291` | `handleRequest` for `.info` / `.mod` / `.zip` only — `@v/list` and `@latest` skipped (decision B) | Only post-download scan on `.zip`. Earlier endpoints currently pass through. |
| Docker | `internal/adapter/docker/docker.go:576` | `handleManifest` (pull only — push gate dropped per decision A) | Only post-download Trivy scan after pulling the full image. |

### Seed-data note (Docker)

The seed (`internal/scanner/builtin/typosquat_data.go`) uses different name conventions per ecosystem:

| Ecosystem | Seed format | Adapter `scanner.Artifact.Name` format | Match? |
|---|---|---|---|
| PyPI | bare canonical name (`requests`) | bare canonical name | ✓ |
| npm | bare or scoped (`lodash`, `@scope/x`) | bare or scoped | ✓ |
| RubyGems | bare name (`rails`) | bare name | ✓ |
| NuGet | PascalCase id (`Newtonsoft.Json`) | id from URL | ✓ |
| Maven | `groupId:artifactId` (`org.springframework:spring-core`) | `groupId:artifactId` (constructed in `maven.go:419`) | ✓ |
| Go (`EcosystemGo = "go"`) | full module path (`github.com/spf13/viper`) | full module path | ✓ |
| **Docker** | **bare image name** (`nginx`) | **safe-name** (`docker_io_library_nginx` from `MakeSafeName`) | **✗ mismatch** |

For Docker the scanner's `normalizeName` reduces both sides to ASCII-dash form, but the resulting Levenshtein distance between `docker_io_library_nginx` and seed entry `nginx` is ~22 — no edit-distance match, no exact-match short-circuit. Today's Docker typosquat coverage is silently zero in the post-scan path. Phase 5 resolves this with a two-name helper signature (scanner sees the user-facing image path, synthetic row stores safeName) and Phase 5 also bundles the seed update so `library/<name>` aliases land at the same time the gate goes live.

## Proposed solution

### Architecture

Phase 0 lands the pre-rollout fixes (integrity bug, dedup, retention, return-tuple change in HasOverride, package-scope-by-default decision) in shared code. Phases 1–5 add the per-adapter integration in the same shape as npm/PyPI. Phase 6 consolidates docs + e2e.

For Docker, the helper takes an `imageNameForScan` argument (user-facing, e.g. `library/nginx` with `library/` stripped if and only if the resolved registry is Docker Hub) separately from the artifact-ID safe-name. The seed is supplemented in Phase 5 with `library/<name>` aliases so the gate has actual coverage.

### Database changes

None to schema. The retention scheduler in Phase 0 reads existing tables (`scan_results`, `audit_log`) and writes `DELETE` statements bounded by a configurable max-age.

### Service layer changes

- `(*scanner.Engine).PreScanTyposquat(ctx, name, ecosystem) (ScanResult, bool)` — unchanged.
- `(*policy.Engine).HasOverride(ctx, ecosystem, name, version) (overrideID int64, ok bool)` — **return type changed in Phase 0**. Callers in `npm.go` and `pypi.go` updated accordingly. The new override-allowed audit entry includes `override_id` in `MetadataJSON`.
- `adapter.PersistTyposquatBlock(db, artifactID, ecosystem, rawName, result, now) error` — **signature changed in Phase 0**: drops the `version` parameter; always writes `version="*"` per decision C. In-process LRU dedup (5-minute TTL keyed by `artifactID`) gates the DB writes.
- `adapter.VerifyUpstreamIntegrity` — **Phase 0 adds the `existingSHA256 == ""` short-circuit.**
- New scheduler task `internal/scheduler/scan_results_audit_retention.go` — modeled on `version_diff_retention.go`, configurable max-age (default 90 days for `scan_results`, **never** for `audit_log` per CLAUDE.md security invariant — actually, re-evaluated below).

  Re-evaluation: CLAUDE.md says `audit_log` is **append-only — no UPDATE or DELETE**. Phase 0 retention therefore does NOT touch `audit_log`; instead, dedup in `PersistTyposquatBlock` collapses repeat-attack writes at source. Operators who need long-term audit storage already have it; operators who care about disk pressure under attack now have rate-of-growth controlled at the producer.

Per-adapter helpers added:

- `(*nuget.NuGetAdapter).blockIfTyposquat(w, r, id, version) bool`
- `(*gomod.GoModAdapter).blockIfTyposquat(w, r, modulePath, version) bool`
- `(*docker.DockerAdapter).blockIfTyposquat(w, r, imageNameForScan, safeName, ref) bool`

Maven and RubyGems use the inline pattern (single hook each).

### UI changes

None — `*` rendering already in place. `ArtifactTable.tsx` and `ArtifactDetailPanel.tsx` were not previously exercised with 4-segment Maven (`maven:org:artifact:version`) or 4-segment RubyGems (`rubygems:name:version:filename`) synthetic rows. **Phase 2 and Phase 3 acceptance now require a UI smoke test** confirming render correctness.

### Configuration

- New optional config field `scanners.typosquat.persist_dedup_window_seconds` (default `300`) controls the in-process LRU TTL in `PersistTyposquatBlock`.
- New optional config field `retention.scan_results_days` (default `90`) for the new retention task.
- No other config changes. The previously-considered `scanners.typosquat.gate_docker_push` flag is **not added** because the push gate is dropped entirely (decision A).

## Affected files

### New files

- `internal/scheduler/scan_results_retention.go` — retention task for `scan_results` (audit_log is append-only; dedup-at-source replaces retention-at-sink for it).
- `internal/scheduler/scan_results_retention_test.go` — unit tests.

### Modified files (Phase 0 — shared infrastructure)

- `internal/adapter/base.go` — fix `VerifyUpstreamIntegrity` empty-SHA case (~3 lines), restructure `PersistTyposquatBlock` to drop `version` param, hard-code `*`, add in-process LRU dedup. Estimated +50 lines / -10 lines.
- `internal/adapter/base_test.go` — update existing tests for new signature, add `TestVerifyUpstreamIntegrity_EmptyExistingSHA_ReturnsNil`, add `TestPersistTyposquatBlock_RepeatedCalls_DedupedWithinWindow`. Estimated +60 lines.
- `internal/adapter/integrity_test.go` — add the regression case. Estimated +30 lines.
- `internal/policy/engine.go` — change `HasOverride` return type to `(int64, bool)`. Estimated +10 lines / -5 lines.
- `internal/policy/engine_db_test.go` — update existing tests for new return tuple. Estimated +20 lines.
- `internal/adapter/npm/npm.go` — adapt to new `HasOverride` and `PersistTyposquatBlock` signatures; add `override_id` to the override-allowed audit entry. Estimated +15 lines / -10 lines.
- `internal/adapter/pypi/pypi.go` — same adaptations. Estimated +15 lines / -10 lines.

### Modified files (Phase 1–5 — per adapter)

- `internal/adapter/nuget/nuget.go` — new `blockIfTyposquat`, calls in `handleRegistration` (line 210) and `handleNupkgDownload` (line 240). Estimated +75 lines.
- `internal/adapter/nuget/nuget_test.go` — registration-level block, download-level block, override release. Estimated +120 lines.
- `internal/adapter/maven/maven.go` — inline block in `downloadScanServe` after `artifactID := mavenArtifactID(...)` (line 293). Estimated +40 lines.
- `internal/adapter/maven/maven_test.go` — block + override release; UI render smoke test. Estimated +120 lines.
- `internal/adapter/rubygems/rubygems.go` — inline block in `downloadScanServe` (line 282). Estimated +40 lines.
- `internal/adapter/rubygems/rubygems_test.go` — block + override release; UI render smoke. Estimated +120 lines.
- `internal/adapter/gomod/gomod.go` — new helper, hooked in `handleRequest` for `reqVersionInfo` / `reqGoMod` / `reqZipDownload` only (decision B). Estimated +90 lines.
- `internal/adapter/gomod/gomod_test.go` — block at each of the 3 hooked types + assert no block at `@v/list` and `@latest` + override release. Estimated +180 lines.
- `internal/adapter/docker/docker.go` — new helper, hook in `handleManifest` only (no push gate, decision A). `library/` stripping conditional on resolved registry being Docker Hub. Estimated +85 lines.
- `internal/adapter/docker/docker_test.go` — pull block (with and without `library/` prefix), override release, non-Docker-Hub fall-through, push-path is NOT gated. Estimated +180 lines.
- `internal/scanner/builtin/typosquat.go` — precompute `HomoglyphSkeleton` in `PopularPackage`, populate at scanner construction, use in `checkHomoglyph`. Estimated +15 lines / -5 lines.
- `internal/scanner/builtin/typosquat_data.go` — Phase 5 adds `library/<name>` aliases for popular Docker images (~10 entries). Estimated +20 lines.
- `internal/api/artifacts.go` — strip popular-package name from public 403 Reason in the typosquat-block response (in adapter helpers, not here — this entry is the audit-log retrieval path which keeps the rich reason).

### Modified files (Phase 6 — docs + e2e)

- `tests/e2e-shell/test_typosquat.sh` — sub-cases per new ecosystem, including 4-segment ID Release calls with `%2F` URL-encoding for slash-bearing IDs. Estimated +130 lines.
- `internal/api/artifacts_test.go` — `TestHandleRelease_4SegmentMavenID_OK`, `TestHandleRelease_GoModSlashID_OK` (covers the `go:github.com/...:*` URL-encoding round-trip). Estimated +60 lines.
- `docs/scanners.md` — replace npm/PyPI-only language; coverage table footer; add allowlist guidance per ecosystem (full module path for Go, `groupId:artifactId` for Maven, bare name for the rest). Estimated +20 lines / -5 lines.
- `docs/features/typosquatting-detection.md` — update "Adapter integration" enumeration; add gomod operator-troubleshooting note ("`go mod tidy` returning 'not found' for a popular-looking module → check the typosquat audit log"); document that `audit_log.event_type='BLOCKED' AND reason LIKE 'typosquat%'` is the canonical query, not HTTP status. Estimated +25 lines / -2 lines.
- `docs/api/openapi.yaml` — explicitly enumerate the ecosystems for which the `*` placeholder behaviour applies, so the spec is descriptive. Estimated +15 lines.

### Unchanged files (deliberately)

- `internal/scanner/engine.go` — `PreScanTyposquat` is ecosystem-agnostic and stays as-is.
- `ui/src/components/ArtifactDetailPanel.tsx`, `ArtifactTable.tsx` — `*` rendering already in place.
- `ui/e2e/typosquat-override.spec.ts` — npm-specific fixture; UI behaviour is ecosystem-agnostic, no change needed.

## Implementation phases

Phases run sequentially. Each phase ends with `make build && make test && make lint` plus the relevant E2E shell test for the touched ecosystem. Per CLAUDE.md "max ~5 files per phase" — Phase 0 touches 7 files but they are tightly-coupled shared infrastructure; the alternative of splitting it muddies the sequencing.

### Phase 0 — Pre-rollout fixes (BLOCKERS)

Resolves the latent integrity bug, sets up retention + dedup, and applies decision C (always package-scope) and the audit-log `override_id` improvement uniformly to npm/PyPI before the rollout reuses the helpers.

- [ ] Fix `VerifyUpstreamIntegrity` empty-SHA case in `internal/adapter/base.go:664-695` — treat `existingSHA256 == ""` as "first download". Add `TestVerifyUpstreamIntegrity_EmptyExistingSHA_ReturnsNil`.
- [ ] Add end-to-end regression test: PyPI typosquat block (existing flow) → admin Release → real package fetch returns 200 (no integrity violation). This locks in the fix for the existing PyPI flow.
- [ ] Change `PersistTyposquatBlock` signature: drop `version` parameter; always store `*`. Update existing npm/PyPI callers.
- [ ] Add in-process LRU dedup to `PersistTyposquatBlock` keyed by `artifactID`, default TTL 5 minutes from `config.TyposquatConfig.PersistDedupWindowSeconds`.
- [ ] Change `(*policy.Engine).HasOverride` return type to `(int64, bool)`. Update existing callers in npm/PyPI to record `override_id` in `MetadataJSON` of the override-allowed audit entry.
- [ ] Detach audit-log writes in `blockIfTyposquat` from the request context (5-second background context) — mirrors `hasDBOverride`.
- [ ] Strip popular-package name from public 403 `Reason` field in `blockIfTyposquat` (npm + PyPI for now). Keep rich description in `scan_results.findings_json` and `audit_log.reason` (admin-only).
- [ ] Add length cap (128 chars) on `name`/`modulePath` argument to `PersistTyposquatBlock` — mirrors `maxNameLength` from typosquat scanner.
- [ ] Precompute homoglyph skeleton in `PopularPackage` struct (`internal/scanner/builtin/typosquat.go:24-28`); populate at construction in `NewTyposquatScanner`; use in `checkHomoglyph`.
- [ ] Add new scheduler task `internal/scheduler/scan_results_retention.go` for `scan_results` only (NOT `audit_log`, which stays append-only per security invariant — the LRU dedup is the audit growth control).
- [ ] Update `docs/scanners.md` and `docs/features/typosquatting-detection.md` to reflect the package-scope-by-default decision and the new Reason-stripping behaviour.

Acceptance: existing npm + PyPI typosquat flow behaviour is unchanged from the user's perspective EXCEPT (a) Release after typosquat block now actually serves the legitimate package on next request (was broken), (b) override-allowed audit entries now include `override_id`, (c) repeated typosquat probes within 5 minutes don't spam `scan_results`. All existing tests pass with updated expectations.

### Phase 1 — NuGet

- [ ] Add `blockIfTyposquat(w, r, id, version)` helper to `internal/adapter/nuget/nuget.go`.
- [ ] Wire into `handleRegistration` (name-only) and `handleNupkgDownload` (version-scoped — but synthetic row uses `*` per Phase 0).
- [ ] Unit tests: `TestNuGetAdapter_TyposquatBlocks_RegistrationLevel_Returns403`, `TestNuGetAdapter_TyposquatBlocks_DownloadLevel_Returns403`, `TestNuGetAdapter_TyposquatOverride_LetsThroughWithAuditLog` (asserts `override_id` in MetadataJSON), `TestNuGetAdapter_ScannerNotRegistered_NoBlock` (fail-safe).
- [ ] E2E acceptance: block → row appears in Artifacts pane (verify via API) → click Release → audit log shows EVENT_RELEASED with override_id → subsequent request no longer 403.

### Phase 2 — Maven

- [ ] Inline block in `internal/adapter/maven/maven.go` `downloadScanServe`. Synthetic row uses `*` (decision C).
- [ ] Unit tests: block at JAR fetch + override release.
- [ ] **UI smoke test:** assert `ArtifactDetailPanel.tsx` correctly renders a Maven 4-segment synthetic row whose name contains a `:` separator. Add to `ui/e2e/`.
- [ ] E2E acceptance: full block→Release→retry round-trip with the URL-encoded 4-segment ID.

### Phase 3 — RubyGems

- [ ] Inline block in `internal/adapter/rubygems/rubygems.go` `downloadScanServe`. Synthetic row uses `*`.
- [ ] Unit tests: block + override release.
- [ ] UI smoke test for 4-segment RubyGems synthetic row rendering.
- [ ] E2E acceptance: full round-trip.

### Phase 4 — gomod

- [ ] `blockIfTyposquat(w, r, modulePath, version) bool` helper.
- [ ] Hook in `handleRequest` for **`reqVersionInfo`, `reqGoMod`, `reqZipDownload` only** (decision B). Skip `reqVersionList` and `reqLatest` to keep `go mod tidy` fast on the name-only enumeration phase.
- [ ] Synthetic row stores `*` (decision C). Artifact ID format: `go:{modulePath}:*` — the ecosystem constant is `EcosystemGo = "go"`, NOT `gomod`.
- [ ] Status code on block: 410 Gone (existing gomod convention; Go clients treat 410 as "module withdrawn, do not retry credentials" — appropriate for typosquat blocks).
- [ ] Unit tests: block at each of the 3 hooked types, assert no block at `@v/list` and `@latest`, override release. Length-cap test (130-char module path → bad request).
- [ ] E2E shell uses `%2F` URL-encoding for the slash-bearing artifact ID when calling Release.

### Phase 5 — Docker

- [ ] `blockIfTyposquat(w, r, imageNameForScan, safeName, ref) bool` helper.
- [ ] **Pull only** (decision A). Hook in `handleManifest`. **No** hook in `handleManifestPut` — push to internal namespaces is an authenticated developer act and the typosquat gate is inappropriate there.
- [ ] `imageNameForScan` derivation: if resolved registry is Docker Hub (`docker.io`) AND `imagePath` starts with `library/`, strip the `library/` prefix; otherwise pass `imagePath` as-is. Document that for non-`library/` Docker Hub paths and non-Docker-Hub registries, typosquat detection relies entirely on whatever the seed contains for that exact prefix.
- [ ] Synthetic row stores `*` for `version` (decision C). Artifact ID format: `docker:{safeName}:*`.
- [ ] **Bundled with this phase: seed update.** Add `library/<name>` aliases to `internal/scanner/builtin/typosquat_data.go` for the existing 40 Docker entries. Without this the Phase 5 acceptance test fails (gate has no seed coverage to compare against).
- [ ] Unit tests: pull block (with `library/` prefix on Docker Hub), pull block (without prefix on non-Docker-Hub registry), override release, **negative test confirming push is NOT gated** (`TestDockerAdapter_PushPath_NotGatedByTyposquat`).
- [ ] E2E: `curl http://gate/v2/library/nginxx/manifests/latest` → 403 → Release → retry succeeds.

### Phase 6 — Docs + e2e + cross-cutting tests

- [ ] Extend `tests/e2e-shell/test_typosquat.sh` with sub-cases per new ecosystem. All sub-cases use proper URL-encoding (`%2F` for slashes, `%2A` for `*`) when hitting the Release API.
- [ ] Add `TestHandleRelease_4SegmentMavenID_OK` and `TestHandleRelease_GoModSlashID_OK` to `internal/api/artifacts_test.go` to lock in the URL-decoding round-trip behaviour.
- [ ] Update `docs/scanners.md`:
  - Drop npm/PyPI-only language in the override subsection.
  - Add per-ecosystem allowlist matching guidance (full module path for Go, `groupId:artifactId` for Maven, bare name for the rest).
  - Document that typosquat blocks are identified by `audit_log.event_type='BLOCKED' AND reason LIKE 'typosquat%'`, not by HTTP status (relevant because gomod uses 410 vs. 403 elsewhere).
  - Note that Docker typosquat protection is scoped to `library/` Docker Hub paths plus whatever operator-supplied seed entries exist for non-`library/` paths.
- [ ] Update `docs/features/typosquatting-detection.md`:
  - Adapter-integration line lists all 6 adapters.
  - Operator troubleshooting note for gomod 410.
  - Note that the override revoke is async with respect to in-flight requests but cached subsequent serves re-evaluate via `hasDBOverride`.
  - Note that `audit_log` is not retained automatically; in-process dedup at `PersistTyposquatBlock` is the growth control.
- [ ] Update `docs/api/openapi.yaml` to enumerate the ecosystems where `*` placeholder applies.

## Risks and mitigations

| Risk | Impact | Probability | Mitigation |
|---|---|---|---|
| **Phase 0 integrity fix breaks an existing happy path** (false negative on real upstream content mutation) | First-time downloads stop being verified | Low | The fix is `if existingSHA256 == "" return nil` — for genuine first downloads `db.Get` returns `sql.ErrNoRows` and we already return nil. The empty-string case can ONLY arise from a synthetic typosquat row, which has no upstream content to compare against anyway. Regression test covers both branches. |
| Docker safe-name vs. seed-name mismatch (existing latent issue) | Pre-scan adds zero value for Docker | High without mitigation | Phase 5 design + Phase 5 seed update fix this together (bundled, not split between phases). |
| Per-IP DoS from typosquat-name flooding | DB write growth, audit_log growth | Medium | LRU dedup in `PersistTyposquatBlock` (Phase 0) caps DB writes per `artifactID` to 1 per 5 minutes. `scan_results` retention task (Phase 0, 90-day default) bounds long-term growth. `audit_log` stays append-only per security invariant; the dedup is its growth control. **Follow-up (not in scope):** per-IP rate limiting middleware — flagged in "Follow-ups" below. |
| `policy_overrides` index does not cover `HasOverride` query | Slow override checks at scale | Low | Index `idx_policy_overrides_unique_active` covers `(ecosystem, name, version, scope)` filtered on `revoked=0`. Phase 0 acceptance includes `EXPLAIN QUERY PLAN` verification. |
| 4-segment Maven/RubyGems IDs and slash-bearing gomod IDs don't round-trip through chi URL routing | Release UX broken for those ecosystems | Medium without test | Phase 6 adds explicit `TestHandleRelease_*` API tests covering both shapes. UI client already uses `encodeURIComponent`; e2e shell sub-cases will use the same encoding (`%2F`, `%2A`). |
| gomod `.info`/`.mod`/`.zip` hook adds 0.5 ms × N modules on `go mod tidy` | Noticeable latency for large projects | Low | Decision B already trims the hook from 5 endpoint types to 3 (skipping `@v/list` and `@latest`). Length-prefilter in Levenshtein keeps per-call cost sub-ms. **Follow-up:** in-memory LRU cache for `(ecosystem, name)` PreScanTyposquat results — flagged below. |
| Operator surprise from "`*` Release creates package-scope override" semantics for ecosystems where the user thought they were releasing a single version | Wrong override scope, future versions wrongly allowed | Medium | Decision C makes this **uniform**: typosquat = name-based detection = name-scoped override. Document in `docs/scanners.md`: "Releasing a typosquat block always creates a package-scoped override; a future version of the same name will not re-block. To apply a tighter scope, revoke the package override and create a manual version-scoped override." |
| End-developer experience for gomod 410 blocks is opaque (`go mod tidy` says "not found") | Operator support burden | Medium | Phase 6 docs add explicit troubleshooting guidance: end developers see "not found"; operators check Artifacts pane. Audit-log query template included. |
| Push-path security regression (decision A drops the push gate) | Internal user might push a typosquat-named image to internal namespace | Low | Pull is where typosquat consumption happens; push gate would punish legitimate internal naming (e.g. `nginz`, `redys`) for no realistic threat-model gain. Internal pushes are authenticated and the operator controls the content. |

## Testing

### Unit tests

Naming pattern `Test{Adapter}_TyposquatBlocks_{Scenario}_{ExpectedOutcome}` per CLAUDE.md.

Phase 0:
- `TestVerifyUpstreamIntegrity_EmptyExistingSHA_ReturnsNil`
- `TestPersistTyposquatBlock_AlwaysStoresPlaceholderVersion`
- `TestPersistTyposquatBlock_RepeatedCalls_DedupedWithinWindow`
- `TestPersistTyposquatBlock_NameOver128Chars_ReturnsError`
- `TestHasOverride_ReturnsOverrideID`

Phase 1 (NuGet) through Phase 5 (Docker):
- `TestNuGetAdapter_TyposquatBlocks_RegistrationLevel_Returns403`
- `TestNuGetAdapter_TyposquatBlocks_DownloadLevel_Returns403`
- `TestNuGetAdapter_TyposquatOverride_LetsThroughWithAuditLogContainingOverrideID`
- `TestNuGetAdapter_ScannerNotRegistered_NoBlock` (fail-safe)
- `TestMavenAdapter_TyposquatBlocks_JarFetch_Returns403`
- `TestMavenAdapter_TyposquatOverride_PackageScopeOverride`
- `TestRubyGemsAdapter_TyposquatBlocks_GemDownload_Returns403`
- `TestRubyGemsAdapter_TyposquatOverride_PackageScopeOverride`
- `TestGoModAdapter_TyposquatBlocks_VersionInfo_Returns410`
- `TestGoModAdapter_TyposquatBlocks_GoMod_Returns410`
- `TestGoModAdapter_TyposquatBlocks_ZipDownload_Returns410`
- `TestGoModAdapter_NoBlock_VersionList` (asserts decision B)
- `TestGoModAdapter_NoBlock_AtLatest` (asserts decision B)
- `TestDockerAdapter_TyposquatBlocks_LibraryPrefixStripped_Returns403`
- `TestDockerAdapter_TyposquatBlocks_NonDockerHub_Registry_NoFalsePositive`
- `TestDockerAdapter_PushPath_NotGatedByTyposquat` (asserts decision A)

Phase 6:
- `TestHandleRelease_4SegmentMavenID_OK`
- `TestHandleRelease_GoModSlashID_OK`

### E2E shell

Each ecosystem gets a 3-step block→Release→retry cycle with proper URL-encoding (`%2F`, `%2A`).

### UI smoke

Phase 2 + Phase 3 add a Playwright check for 4-segment ID rendering in the Artifacts pane.

### Verification

```bash
make build
make test
make lint
./tests/e2e-shell/run_all.sh
```

Grep checks:

```bash
# Confirm every adapter has the integration:
grep -l "PreScanTyposquat\|blockIfTyposquat" internal/adapter/*/

# Confirm no adapter is missing the override check:
grep -B2 -A6 "PreScanTyposquat" internal/adapter/*/*.go | grep -L "HasOverride"

# Confirm gomod artifact ID prefix is "go:" not "gomod:" everywhere:
grep -rn 'gomod:' internal/ tests/ docs/ | grep -v 'gomod\.go\|gomod_test\.go\|adapter/gomod' | grep -v 'docs/plans/'
```

## Notes

- **Idempotence:** `PersistTyposquatBlock` uses `INSERT … ON CONFLICT DO UPDATE` for `artifacts` and `artifact_status`. Phase 0 dedup ensures `scan_results` rows are also bounded (1 row per `artifactID` per dedup window). `audit_log` continues to grow per request; LRU dedup gates whether the `BLOCKED` event fires more than once per window per `artifactID`.
- **Backward compatibility:** No API contract changes. The `*` version sentinel and 4-segment artifact IDs (Maven/RubyGems) were already in production for non-typosquat full-scan paths.
- **Performance:** Pre-scan adds one in-memory call (`PreScanTyposquat`, sub-ms after Phase 0 homoglyph precompute) and one indexed DB COUNT(*) (`HasOverride`, sub-ms) before each metadata/download request that would have happened anyway. Post-Phase-0 dedup means repeated typosquat-name probes are O(1) DB writes.
- **Security invariants preserved:**
  - Never serve a quarantined artifact: synthetic rows go straight to QUARANTINED status.
  - Never trust unscanned content: pre-scan runs before upstream fetch; can only block, never allow.
  - Never log secrets: new log/audit entries carry only artifact IDs and verdict strings.
  - Audit log append-only: dedup at producer, not retention at sink.
- **Override revoke TOCTOU:** revoke is async w.r.t. in-flight requests; the typosquat-only override path does not re-check at serve time. The full-scan adapter path re-evaluates via `hasDBOverride` in `policy.Evaluate`. Documented explicitly in Phase 6.
- **Cache-quarantined vs. override TOCTOU:** if a synthetic typosquat block is written and then overridden, future cache-hit checks (which run before the typosquat pre-scan path) see status=QUARANTINED and block. Resolution: admin Release sets `artifact_status.status='CLEAN'` for the synthetic row, so cache hits also unblock. This is the existing npm/PyPI behaviour — verified working after Phase 0's integrity fix.

## Follow-ups (NOT in scope)

Tracked for future work — flagged by reviewers as desirable but not blockers:

- **In-memory LRU cache for `PreScanTyposquat` results** keyed by `(ecosystem, name)`, short TTL (1–5 s). Reduces hot-path scan cost for `go mod tidy` and Docker CI pull patterns. Requires no invalidation (the underlying scanner state is immutable for the process lifetime).
- **In-memory LRU cache for `HasOverride` results** with explicit invalidation on override create/revoke in `internal/api/artifacts.go`. Removes redundant DB hits for repeat probes within a `tidy` session.
- **Per-IP rate limiting middleware** using `golang.org/x/time/rate` (already in `go.mod`). Adds defense against typosquat-name flooding at request ingress.
- **Multi-tenant project_id on synthetic typosquat rows.** Today the proxy is single-tenant; if multi-tenant ships, the synthetic rows are global and reveal the seed contents to any tenant admin. Mitigation: stamp `project_id` on the synthetic row (already in `WriteAuditLogCtx` for the audit entry, just not on the artifact itself).

## References

- Implementation reference: `internal/adapter/npm/npm.go:632-701`, `internal/adapter/pypi/pypi.go:248-293`.
- Existing helpers: `internal/scanner/engine.go:139`, `internal/policy/engine.go:222`, `internal/adapter/base.go:545`.
- API integration: `internal/api/artifacts.go:553-561` (Release → package-scope override).
- Feature documentation: `docs/features/typosquatting-detection.md`.
- Scanner documentation: `docs/scanners.md` (override workflow subsection at line 97).
- Seed data: `internal/scanner/builtin/typosquat_data.go` (counts: PyPI 159, npm 188, RubyGems 90, NuGet 78, Docker 40, Maven 76, Go 82).
- Recent commits: `7b77235` (initial npm/PyPI implementation), `70c0153` (CodeRabbit fixes).
- Cross-check reviews dispatched 2026-05-02: BA (verdict: needs revision), Dev (minor issues), Security (needs improvement), Perf (needs optimization). v2 incorporates feedback per documented decisions A (drop Docker push gate), B (gomod hook scope = `.info` + `.mod` + `.zip` only), C (always package-scope for typosquat blocks).
