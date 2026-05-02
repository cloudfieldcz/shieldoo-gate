---
status: DRAFT — awaiting cross-check review
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

This analysis plans the rollout of that pattern to the remaining 5 adapters: **NuGet**, **Maven**, **RubyGems**, **gomod**, **Docker**.

### Why

- **Parity.** Operators already see typosquat blocks for npm and PyPI. The same UX (block at the earliest possible point, persist a synthetic QUARANTINED row, allow Release → override) should apply to every ecosystem the proxy supports.
- **Defense in depth.** The current state is silently inconsistent: a typosquat package on NuGet/Maven/etc. only gets caught after a full download → scan pipeline, which means the proxy contacts upstream, downloads the artifact, and pays the scan cost for content that should never have been fetched. The pre-scan gate prevents that round-trip and the corresponding upstream traffic that confirms a typosquat name exists.
- **No new scanner work.** The `builtin-typosquat` scanner already declares support for all 7 ecosystems (`internal/scanner/builtin/typosquat.go:93-103`) and the seed table already has popular-package coverage in each. This is purely an adapter-integration project.
- **Reduced operator surprise.** The `version="*"` placeholder + Release-to-package-scope-override mechanism is documented in `docs/scanners.md` as a general behaviour. Today only npm/PyPI exhibit it, which makes the documentation aspirational rather than descriptive.

## Current state

### Reference implementation: npm

`internal/adapter/npm/npm.go` exposes a private helper, `blockIfTyposquat(w, r, pkgName, version)`, called from 5 routes (lines 138, 152, 179, 198, 288):

- `handlePackageMetadata` and `handleScopedPackageMetadata` — name-only (version="").
- `handleVersionMetadata` and `handleScopedVersionMetadata` — version-scoped.
- `handleTarballDownload` — version-scoped, with version derived from the tarball filename.

The helper itself (`internal/adapter/npm/npm.go:632-701`):

1. Calls `a.scanEngine.PreScanTyposquat(ctx, pkgName, EcosystemNPM)`. Returns false (no block) if the scanner is not registered or the verdict is `CLEAN`.
2. Sanitizes the package name (`/` → `_`, `@` removed) and substitutes `adapter.TyposquatPlaceholderVersion` (`"*"`) for empty versions, then composes the canonical artifact ID `npm:{sanitizedName}:{version|*}`.
3. Calls `policyEngine.HasOverride(ctx, EcosystemNPM, pkgName, version)`. If an override exists, writes an `EVENT_SERVED` audit entry with the artifact ID and returns false (let the caller continue).
4. Otherwise: logs the block, calls `adapter.PersistTyposquatBlock()` to write the synthetic artifact + QUARANTINED status + `scan_results` rows, returns 403 JSON, and writes an `EVENT_BLOCKED` audit entry. Returns true so the caller can stop.

### Reference implementation: PyPI

`internal/adapter/pypi/pypi.go:248-293` inlines the same pattern (no helper) inside `downloadScanServe`, run after the cache lookup but before the upstream download. PyPI does not expose a separate metadata-fetch route — the simple-index page is rewritten to point downloads back through the proxy, so all blocks happen at version-scoped tarball requests.

### Shared infrastructure (already in place)

- `internal/scanner/engine.go:139-159` — `(e *Engine) PreScanTyposquat(ctx, name, ecosystem)` walks the registered scanners, finds `builtin-typosquat`, and runs a name-only scan. Returns `(ScanResult, true)` on success, `(zero, false)` if no typosquat scanner is registered (e.g. configured off).
- `internal/policy/engine.go:222-256` — `(e *Engine) HasOverride(ctx, ecosystem, name, version)` runs the same `policy_overrides` query that `Evaluate` uses, on a 5-second detached context. Empty version causes only `scope='package'` rows to match.
- `internal/adapter/base.go:545-604` — `TyposquatPlaceholderVersion = "*"` and `PersistTyposquatBlock(db, artifactID, ecosystem, rawName, version, result, now)`. Stores the original (unsanitized) name in `artifacts.name` so override matching against `scanner.Artifact.Name` works downstream.
- `internal/api/artifacts.go:553-561` — `handleReleaseArtifact` detects `version == TyposquatPlaceholderVersion` and creates a `scope='package'` override with empty version.
- `ui/src/components/ArtifactDetailPanel.tsx` and `ArtifactTable.tsx` — render `*` as `(any version)` for these synthetic rows.

### Current gap per adapter

| Adapter | File / lines | Where pre-scan should hook | Block site coverage today |
|---|---|---|---|
| NuGet | `internal/adapter/nuget/nuget.go:210, 240, 265` | `handleRegistration` (name-only), `handleNupkgDownload` (version-scoped) | Only post-download Trivy scan. |
| Maven | `internal/adapter/maven/maven.go:124-170, 290` | `handleRequest` for parsed scannable paths (groupId+artifactId+version-scoped) | Only post-download Trivy scan on `.jar/.war/.aar/.zip`. |
| RubyGems | `internal/adapter/rubygems/rubygems.go:180, 280` | `handleGemDownload` → `downloadScanServe` (version-scoped, name+version derived from filename) | Only post-download scan. |
| gomod | `internal/adapter/gomod/gomod.go:115-138, 291` | `handleRequest` for **all** parsed request types (list/info/mod/zip/latest) | Only post-download scan on `.zip`. Earlier endpoints (`@v/list`, `.info`, `.mod`) currently pass through without typosquat checks. |
| Docker | `internal/adapter/docker/docker.go:175, 576, 370` | `handleManifest` (pull, version-scoped on ref) and optionally `handleManifestPut` (push) | Only post-download Trivy scan after pulling the full image. |

### Seed-data note (CRITICAL for Docker)

The seed (`internal/scanner/builtin/typosquat_data.go`) uses different name conventions per ecosystem:

| Ecosystem | Seed format | Adapter `scanner.Artifact.Name` format | Match? |
|---|---|---|---|
| PyPI | bare canonical name (`requests`) | bare canonical name | ✓ |
| npm | bare or scoped (`lodash`) | bare or scoped (`@scope/x`) | ✓ |
| RubyGems | bare name (`rails`) | bare name | ✓ |
| NuGet | PascalCase id (`Newtonsoft.Json`) | id from URL (`Newtonsoft.Json`) | ✓ |
| Maven | `groupId:artifactId` (`org.springframework:spring-core`) | `groupId:artifactId` (constructed in `maven.go:419`) | ✓ |
| Go | full module path (`github.com/spf13/viper`) | full module path | ✓ |
| **Docker** | **bare image name** (`nginx`) | **safe-name** (`docker_io_library_nginx` from `MakeSafeName`) | **✗ mismatch** |

For Docker the scanner's `normalizeName` reduces both sides to ASCII-dash form, but the resulting Levenshtein distance between e.g. `docker_io_library_nginx` (→ `docker-io-library-nginx`) and seed entry `nginx` is ~22 — no edit-distance match, no exact-match short-circuit. **Today's Docker typosquat coverage is effectively zero in the post-scan path too**, but no one has noticed because Trivy is the dominant signal for Docker. This rollout must address the mismatch, otherwise the pre-scan gate adds no value for Docker.

## Proposed solution

### Architecture

Each remaining adapter gets the same pattern as npm: a `blockIfTyposquat` private helper (or inlined block, matching the PyPI style for adapters with a single hook point) that runs before any upstream request, persists a synthetic block, and consults `HasOverride` to honour admin releases. Hook locations are dictated by the protocol shape of each adapter:

- **Single helper, multiple hooks:** NuGet (registration + download), gomod (5 request types), Docker (pull manifest + push manifest).
- **Inline single-hook:** Maven and RubyGems — only one entry point (`downloadScanServe`).

For Docker, the helper additionally takes an `imageNameForScan` argument (the user-facing image path, e.g. `library/nginx` or `myorg/myapp`) separately from the artifact-ID safe-name. The scanner sees `imageNameForScan`; the synthetic artifact row stores `safeName` so the existing artifact-ID convention is preserved and the Release flow continues to work without API changes. The seed gets supplemental Docker entries that match the user-facing form (covered in Phase 6).

### Per-adapter detail

#### Phase 1 — NuGet

`internal/adapter/nuget/nuget.go`

- New helper `blockIfTyposquat(w, r, id, version)`:
  - Sanitization: NuGet IDs already match `validNameRe` (alnum + `._-`), no further sanitization needed.
  - Artifact ID format: `nuget:{id}:{version|*}` (matches `nuget.go:267`).
- Call sites:
  - `handleRegistration` (line 210), after `ValidatePackageName`, before `proxyUpstreamRewrite` — name-only (version="").
  - `handleNupkgDownload` (line 240), after `ValidateVersion`, before `downloadScanServe` — pass actual version.
- Audit entry style identical to npm. Returns 403 with the same `ErrorResponse` shape.

#### Phase 2 — Maven

`internal/adapter/maven/maven.go`

- Inline block in `downloadScanServe` (line 290), after `artifactID := mavenArtifactID(...)` and before the cache lookup. Hook only here — `.pom` and other passthroughs don't go through `downloadScanServe` and we deliberately do not extend the gate to passthrough paths (POMs are metadata, blocking them would break dependency resolution for legitimate transitive lookups; the JAR fetch is the right gate).
- Name passed to scanner: `parsed.groupID + ":" + parsed.artifactID` — already constructed at `maven.go:419` for `scanArtifact.Name`. The seed uses the same format. ✓
- Artifact ID format: 4-segment `maven:{groupID}:{artifactID}:{version}` (matches `maven.go:254`). The placeholder doesn't apply for Maven since `downloadScanServe` is only ever called with a real version.
- Synthetic row: `rawName = parsed.groupID + ":" + parsed.artifactID`, `version = parsed.version`. The Release flow's `version != "*"` branch creates a version-scoped override naturally.

#### Phase 3 — RubyGems

`internal/adapter/rubygems/rubygems.go`

- Inline block in `downloadScanServe` (line 280), after `artifactID := rubygemsArtifactID(...)` and before the cache lookup. Same shape as Maven — only one entry point matters because RubyGems metadata pass-throughs don't bring in an artifact.
- Name passed to scanner: bare `name`. Seed format matches. ✓
- Artifact ID format: 4-segment `rubygems:{name}:{version}:{filename}` (matches `rubygems.go:175`). Always has a real version (derived from filename).

#### Phase 4 — gomod

`internal/adapter/gomod/gomod.go`

- New helper `blockIfTyposquat(w, r, modulePath, version)`. Returns true on block.
- Hook in `handleRequest` (line 115), **before** the dispatch switch — block applies to every parsed request type (list/info/mod/zip/latest):
  - For `reqVersionList`, `reqLatest`: pass version="" (name-only). Synthetic row stores version="*".
  - For `reqVersionInfo`, `reqGoMod`, `reqZipDownload`: pass `parsed.version`. Synthetic row stores the actual version.
- Name passed to scanner: full `parsed.modulePath` (e.g. `github.com/spf13/viper`). Seed format matches. ✓
- Artifact ID format: `gomod:{modulePath}:{version|*}` (matches `gomod.go:254`). Note: module path contains `/` and `.` — chi URL routing for the artifact ID uses URL-encoding, the existing API handler in `internal/api/artifacts.go:71-77` already calls `url.PathUnescape`, so synthetic IDs containing slashes work the same as regular gomod IDs.
- Status code on block: gomod uses `410 Gone` for quarantined artifacts (line 307) per Go convention. We mirror that for typosquat blocks (return 410, not 403). Update `handleReleaseArtifact` is not needed because the API path is unchanged.

#### Phase 5 — Docker

`internal/adapter/docker/docker.go`

- New helper `blockIfTyposquat(w, r, imageNameForScan, safeName, ref)`. The two-name signature is the design accommodation for Docker's safe-name vs. seed-name mismatch.
- `imageNameForScan`: derived in the helper as the user-facing image path. For `Resolve("library/nginx")` returning `imagePath="library/nginx"`, we strip the `library/` prefix when present so the seed entry `nginx` matches. For other registries/namespaces (`bitnami/postgres`, `ghcr.io/foo/bar`), pass `imagePath` as-is.
- `safeName`: `MakeSafeName(registry, imagePath)` — used only for the synthetic artifact ID so it lines up with regular Docker artifact IDs.
- Artifact ID format: `docker:{safeName}:{ref}` (matches `docker.go:584`). `ref` is the manifest ref (tag or digest). Always present.
- Hook locations:
  - `handleManifest` (line 576), after `safeName := MakeSafeName(...)` and before the cache lookup — covers all pulls.
  - `handleManifestPut` (line 370) — push path. Push of a typosquat-named image to an internal namespace is a defensive concern (someone uploading `nginxx` to internal). Apply the same gate, but pass `imageNameForScan` derived from the push name (no `library/` stripping, since push goes to internal namespace).
- Status code: 403 for both pull and push (matches Docker's existing block convention at lines 597 and 444).
- `serveInternalManifest` and `serveInternalBlob` paths do not need the gate — they only fire after a successful push that already passed the gate.
- **Seed update:** add common Docker Hub `library/<name>` aliases as well as a few popular non-library official images, so users hitting `library/<name>` paths also benefit. See Phase 6.

#### Phase 6 — Docs, seed, e2e shell

This phase consolidates the cross-cutting changes — kept separate so the per-adapter phases stay scoped to a single module per CLAUDE.md.

- `internal/scanner/builtin/typosquat_data.go`: add `library/<name>` aliases for popular Docker images. Idempotent re-seed already exists (`ON CONFLICT DO NOTHING`), so existing deployments pick the new entries up on next start.
- `tests/e2e-shell/test_typosquat.sh`: extend with sub-cases for each new ecosystem mirroring the npm/PyPI checks (block → 403 or 410 for gomod, persistence as QUARANTINED, override flow). Each ecosystem only adds 3 cases (block, persisted, override re-fetch) so the file grows by ~80 lines.
- `docs/scanners.md`: update the "Override workflow" subsection to drop the npm/PyPI-specific phrasing and the ecosystem-coverage matrix at the bottom of the file.
- `docs/features/typosquatting-detection.md`: update the "Adapter integration" line (currently says "Both PyPI and npm adapters call PreScanTyposquat()") to enumerate all 6 adapters.
- `docs/api/openapi.yaml`: no changes — the `*` version semantics for Release are already documented.

### Database changes

None. The `popular_packages`, `policy_overrides`, `artifacts`, `artifact_status`, `scan_results`, and `audit_log` schemas are all already in place and have been exercised by npm/PyPI.

### Service layer changes

No new service interfaces. The existing helpers cover everything:

- `(*scanner.Engine).PreScanTyposquat(ctx, name, ecosystem) (ScanResult, bool)`
- `(*policy.Engine).HasOverride(ctx, ecosystem, name, version) bool`
- `adapter.PersistTyposquatBlock(db, artifactID, ecosystem, rawName, version, result, now) error`
- `adapter.TyposquatPlaceholderVersion = "*"`

Per-adapter helpers added:

- `(*nuget.NuGetAdapter).blockIfTyposquat(w, r, id, version) bool`
- `(*gomod.GoModAdapter).blockIfTyposquat(w, r, modulePath, version) bool`
- `(*docker.DockerAdapter).blockIfTyposquat(w, r, imageNameForScan, safeName, ref) bool`

Maven and RubyGems use the inline pattern (one call site each), matching PyPI.

### UI changes

None — the existing `*` rendering in `ArtifactDetailPanel.tsx` and `ArtifactTable.tsx` already handles synthetic rows from any ecosystem. The Playwright test (`ui/e2e/typosquat-override.spec.ts`) is npm-specific by virtue of the test fixture but doesn't need to change because the UI behaviour is ecosystem-agnostic.

### Configuration

No config changes. `scanners.typosquat.*` settings (top_packages_count, max_edit_distance, allowlist, combosquat_suffixes, internal_namespaces) apply ecosystem-agnostically, and the runtime registration of the typosquat scanner is global.

## Affected files

### New files

- None.

### Modified files

- `internal/adapter/nuget/nuget.go` — new `blockIfTyposquat` helper, calls in `handleRegistration` (line 210) and `handleNupkgDownload` (line 240). Imports add `model`, `time`, `log` (already present). Estimated +75 lines.
- `internal/adapter/nuget/nuget_test.go` — new unit tests (`TestNuGetAdapter_TyposquatBlocks_RegistrationLevel`, `TestNuGetAdapter_TyposquatBlocks_DownloadLevel`, `TestNuGetAdapter_TyposquatOverride_LetsThrough`). Estimated +120 lines.
- `internal/adapter/maven/maven.go` — inline block in `downloadScanServe` after `artifactID := mavenArtifactID(...)` (line 293). Estimated +50 lines.
- `internal/adapter/maven/maven_test.go` — new unit tests covering block at JAR fetch + override release. Estimated +100 lines.
- `internal/adapter/rubygems/rubygems.go` — inline block in `downloadScanServe` after `artifactID := rubygemsArtifactID(...)` (line 282). Estimated +50 lines.
- `internal/adapter/rubygems/rubygems_test.go` — same as Maven. Estimated +100 lines.
- `internal/adapter/gomod/gomod.go` — new `blockIfTyposquat` helper, called in `handleRequest` (line 115) before the dispatch switch. Estimated +85 lines.
- `internal/adapter/gomod/gomod_test.go` — new unit tests covering block at all 5 request types + override release. Estimated +150 lines.
- `internal/adapter/docker/docker.go` — new `blockIfTyposquat` helper, calls in `handleManifest` (line 576) and `handleManifestPut` (line 370). Estimated +110 lines.
- `internal/adapter/docker/docker_test.go` — new unit tests covering pull block, push block, override release. Estimated +180 lines.
- `internal/scanner/builtin/typosquat_data.go` — add `library/nginx`, `library/alpine`, etc. (~10 new entries). Estimated +20 lines.
- `tests/e2e-shell/test_typosquat.sh` — sub-cases per new ecosystem. Estimated +100 lines.
- `docs/scanners.md` — replace npm/PyPI-only language in the override subsection; update coverage table footer. Estimated +10 lines, -5 lines.
- `docs/features/typosquatting-detection.md` — update "Adapter integration" enumeration. Estimated +5 lines, -2 lines.

### Unchanged files (deliberately)

- `internal/adapter/base.go` — `PersistTyposquatBlock` and `TyposquatPlaceholderVersion` already work for any ecosystem. No new helpers needed.
- `internal/policy/engine.go` — `HasOverride` is ecosystem-agnostic.
- `internal/scanner/engine.go` — `PreScanTyposquat` is ecosystem-agnostic.
- `internal/api/artifacts.go` — `handleReleaseArtifact` already maps `*` → package-scope. The 4-segment Maven/RubyGems IDs are already URL-decoded correctly by `artifactID()` (line 70).
- `ui/src/components/ArtifactDetailPanel.tsx`, `ArtifactTable.tsx` — `*` rendering already in place.
- `ui/e2e/typosquat-override.spec.ts` — npm-specific fixture; UI behaviour is ecosystem-agnostic, no change needed.
- `docs/api/openapi.yaml` — `*` semantics already documented.

## Implementation phases

Phases run sequentially (per CLAUDE.md "Each task should map to one module"). Each phase ends with `make build && make test && make lint` plus the relevant E2E shell test for the touched ecosystem. Phases 1–5 each touch ≤3 files in the adapter directory, well within the "max ~5 files per phase" limit.

### Phase 1 — NuGet

- [ ] Add `blockIfTyposquat` helper to `internal/adapter/nuget/nuget.go`.
- [ ] Wire into `handleRegistration` and `handleNupkgDownload`.
- [ ] Unit tests: registration-level block, download-level block, override-allowed override.
- [ ] Verification: `go test ./internal/adapter/nuget/...`, `make build`, `make lint`.
- Expected outcome: requesting `Newt0nsoft.Json` (typosquat of `Newtonsoft.Json`) at `/v3/registration/.../index.json` returns 403 with a synthetic artifact at `nuget:Newt0nsoft.Json:*` visible in the Artifacts pane.

### Phase 2 — Maven

- [ ] Inline block in `internal/adapter/maven/maven.go` `downloadScanServe`.
- [ ] Unit test for typosquat at JAR fetch + override release.
- [ ] Verification commands as above.
- Expected outcome: requesting `org.springframwork:spring-core` JAR (typo) returns 403 before download.

### Phase 3 — RubyGems

- [ ] Inline block in `internal/adapter/rubygems/rubygems.go` `downloadScanServe`.
- [ ] Unit test for block + override.
- [ ] Verification commands as above.
- Expected outcome: requesting `rals-7.0.0.gem` (typo of `rails`) returns 403 before download.

### Phase 4 — gomod

- [ ] `blockIfTyposquat` helper, hook in `handleRequest` before dispatch.
- [ ] Unit tests covering block at each request type (list, info, mod, zip, latest) + override re-fetch.
- [ ] Verification commands as above.
- Expected outcome: `go get github.com/spf12/viper` (typo of `spf13`) returns 410 with persistence as `gomod:github.com/spf12/viper:*` (or version-scoped if hitting `.info`/`.mod`/`.zip`).

### Phase 5 — Docker

- [ ] `blockIfTyposquat` helper with two-name signature, hook in `handleManifest` (pull) and `handleManifestPut` (push).
- [ ] Strip-`library/`-prefix logic for the scanner-facing name.
- [ ] Unit tests: pull block (with and without `library/` prefix), push block to internal namespace, override release.
- [ ] Verification commands as above.
- Expected outcome: `docker pull nginxx` returns 403 with persistence at `docker:docker_io_library_nginxx:latest`.

### Phase 6 — Docs, seed, e2e shell

- [ ] Add Docker `library/<name>` aliases to `typosquat_data.go`.
- [ ] Extend `tests/e2e-shell/test_typosquat.sh` with one block + one override sub-case per new ecosystem.
- [ ] Update `docs/scanners.md` and `docs/features/typosquatting-detection.md` adapter-integration text.
- [ ] Verification: full E2E shell suite.
- Expected outcome: documentation matches the code; the shell suite covers all 7 ecosystems.

## Risks and mitigations

| Risk | Impact | Probability | Mitigation |
|---|---|---|---|
| Docker name mismatch — pre-scan compares `safeName` vs seed `nginx`, distance is huge, scanner returns Clean | Pre-scan adds zero value for Docker (silent design failure) | High without mitigation | Phase 5 design uses two-name signature: scanner sees `imageNameForScan` (with `library/` stripped), synthetic row stores `safeName`. Phase 6 adds `library/<name>` aliases to seed. |
| Maven/RubyGems 4-segment artifact IDs include filename → IDs containing `:` cause issues in chi URL routing | Release flow API call returns 404 for synthetic typosquat rows | Low | Already in production for non-typosquat 4-segment IDs (regular Maven JARs, RubyGems gems already use this format and the API handles them). The synthetic IDs use the same format. |
| gomod typosquat hooks in `handleRequest` block legitimate `@v/list` for typosquat-similar names → `go mod tidy` breaks for users with naming-similar internal modules | Operator confusion, false positives | Medium | Mitigation 1: documented allowlist (`scanners.typosquat.allowlist`) already supports per-name exemptions. Mitigation 2: namespace-confusion strategy is opt-in via config. Mitigation 3: edit-distance proportion guard (`maxDist = nameLen * 0.4`) keeps short module path components from triggering false positives. |
| Override-flow regression: a Maven/RubyGems block that creates a 4-segment artifact ID may not correctly create a version-scoped override on Release | Operator releases a block, but pre-scan still blocks the next request | Low | `handleReleaseArtifact` (`internal/api/artifacts.go:537`) reads `(ecosystem, name, version)` from the DB and matches it via `policyEngine.HasOverride()` — this is data-driven, not ID-format-driven, so 4-segment IDs work the same as 3-segment. Existing tests (`internal/policy/engine_db_test.go`) cover the override matching. Phase 2 and Phase 3 tests will exercise it end-to-end. |
| Docker push block breaks legitimate internal pushes whose names happen to be edit-distance ≤2 from a Docker Hub popular image (e.g. internal `nginz` namespace) | Internal devs cannot push to their own namespace | Medium | Document that `scanners.typosquat.allowlist` should include internal namespace prefixes. Alternative: only run the gate on push when the resolver indicates an external/upstream namespace, never for internal. Decision deferred to BA review. |
| Existing typosquat blocks for npm/PyPI continue to work (regression check) | Persisted blocks suddenly break | Low | The ecosystem-agnostic helpers (`PreScanTyposquat`, `HasOverride`, `PersistTyposquatBlock`) are not modified. Phase 1–5 are additive in their adapters. |
| Increased database write load — every typosquat-name request now writes a synthetic artifact + status + scan_results triple even when blocked | Hot-path DB churn under typosquat scanning attacks | Medium | `PersistTyposquatBlock` uses `INSERT … ON CONFLICT DO UPDATE` (idempotent). Repeated requests for the same name + version → one upserted row, append-only `scan_results`. Mitigation if `scan_results` grows: existing retention policy applies. Optionally: dedupe within a short TTL window — explicit follow-up only if metrics show it. |
| gomod 410 vs npm/PyPI 403 inconsistency surfaces in audit dashboards | Cosmetic — alerts/queries that filter on status code may need updating | Low | Already inconsistent today between gomod and other adapters for regular blocks; we mirror the existing convention. Documented in `docs/scanners.md` Phase 6 update. |

## Testing

### Unit tests

Each adapter phase adds tests with the naming pattern `Test{Adapter}_TyposquatBlocks_{Scenario}_{ExpectedOutcome}` (per CLAUDE.md test naming convention):

- `TestNuGetAdapter_TyposquatBlocks_RegistrationLevel_Returns403`
- `TestNuGetAdapter_TyposquatBlocks_DownloadLevel_Returns403`
- `TestNuGetAdapter_TyposquatOverride_LetsThroughWithAuditLog`
- `TestMavenAdapter_TyposquatBlocks_JarFetch_Returns403`
- `TestMavenAdapter_TyposquatOverride_LetsThroughWithAuditLog`
- `TestRubyGemsAdapter_TyposquatBlocks_GemDownload_Returns403`
- `TestRubyGemsAdapter_TyposquatOverride_LetsThroughWithAuditLog`
- `TestGoModAdapter_TyposquatBlocks_VersionList_Returns410`
- `TestGoModAdapter_TyposquatBlocks_VersionInfo_Returns410`
- `TestGoModAdapter_TyposquatBlocks_ZipDownload_Returns410`
- `TestGoModAdapter_TyposquatOverride_LetsThroughWithAuditLog`
- `TestDockerAdapter_TyposquatBlocks_ManifestPull_Returns403`
- `TestDockerAdapter_TyposquatBlocks_LibraryPrefixStripped_Returns403` — verifies `library/nginxx` triggers a block
- `TestDockerAdapter_TyposquatBlocks_ManifestPush_Returns403`
- `TestDockerAdapter_TyposquatOverride_LetsThroughWithAuditLog`

Each test follows the existing pattern from `internal/adapter/npm/npm_test.go:34, 276` — instantiates a real `TyposquatScanner` against an in-memory SQLite DB seeded with a small popular_packages set, runs the request through the adapter, asserts the HTTP status, the synthetic artifact row, and the audit log.

### Integration / manual tests

Already covered by the extended `tests/e2e-shell/test_typosquat.sh`:

- NuGet: `curl http://gate/v3/registration/Newt0nsoft.Json/index.json` → 403, then `POST /api/v1/artifacts/nuget:Newt0nsoft.Json:*/release` → subsequent fetch no longer 403.
- Maven: `curl http://gate/org/springframwork/spring-core/6.0.0/spring-core-6.0.0.jar` → 403.
- RubyGems: `curl http://gate/gems/rals-7.0.0.gem` → 403.
- gomod: `curl http://gate/github.com/spf12/viper/@v/list` → 410.
- Docker: `curl http://gate/v2/library/nginxx/manifests/latest` → 403.

### Verification

After each phase:

```bash
make build           # adapter compiles
go test ./internal/adapter/<name>/...
make lint
```

After Phase 6:

```bash
make test            # full unit + integration suite
./tests/e2e-shell/run_all.sh   # full E2E shell suite
```

Grep checks:

```bash
# Confirm every adapter has the integration:
grep -l "PreScanTyposquat\|blockIfTyposquat" internal/adapter/*/

# Confirm no adapter is missing the override check:
grep -B2 -A6 "PreScanTyposquat" internal/adapter/*/*.go | grep -L "HasOverride"
```

## Notes

- **Idempotence:** `PersistTyposquatBlock` uses `INSERT … ON CONFLICT DO UPDATE` for both `artifacts` and `artifact_status`, and appends to `scan_results`. Repeated typosquat requests for the same (ecosystem, name, version) produce one artifact row and a growing `scan_results` history — same shape as full-scan persistence. Append-only `audit_log` continues to grow per request.
- **Backward compatibility:** No API contract changes. Existing typosquat blocks for npm/PyPI continue to behave identically. The `*` version sentinel and the `4-segment` artifact IDs (Maven/RubyGems) were already in production for full-scan paths.
- **Performance:** Pre-scan adds one in-memory call (`PreScanTyposquat`) and one cheap DB count query (`HasOverride`) before each metadata/download request that would have happened anyway. Both are sub-millisecond. The previously-paid post-scan cost is removed for typosquat names (no upstream fetch, no scan engine pass, no cache write). Net win on the typosquat-name hot path.
- **Edge case — Maven `:` in artifact ID:** chi route handlers receive `:` as a literal in URL-decoded path params; the existing 4-segment Maven IDs prove this works in production.
- **Edge case — Docker push of internal namespaces:** the `IsPushAllowed` check in `handleV2WildcardWrite` already restricts push to configured internal namespaces. Typosquat block fires before that check, which is intentional (we'd rather block the request early); but operators must be aware their internal namespaces should not collide with Docker Hub popular names. Documented in Phase 6.
- **Open question — gomod request types where to hook:** Phase 4 hooks at `handleRequest` (covers all 5 request types). Alternative: hook only at `reqZipDownload` (matches `downloadScanServe`-only style of Maven/RubyGems). Trade-off: hooking at all types catches typosquats at `go mod tidy` time (before download); hooking only at zip means the `.info`/`.mod`/`.list` requests still hit upstream, which leaks information that the typosquat name was looked up. Recommendation: hook at `handleRequest` (current plan) for parity with npm metadata-time blocks.

## References

- Implementation reference: `internal/adapter/npm/npm.go:632-701`, `internal/adapter/pypi/pypi.go:248-293`.
- Existing helpers: `internal/scanner/engine.go:139`, `internal/policy/engine.go:222`, `internal/adapter/base.go:545`.
- API integration: `internal/api/artifacts.go:553-561` (Release → package-scope override).
- Feature documentation: `docs/features/typosquatting-detection.md`.
- Scanner documentation: `docs/scanners.md` (override workflow subsection at line 97).
- Seed data: `internal/scanner/builtin/typosquat_data.go` (counts: PyPI 159, npm 188, RubyGems 90, NuGet 78, Docker 40, Maven 76, Go 82).
- Recent commits: `7b77235` (initial npm/PyPI implementation), `70c0153` (CodeRabbit fixes).
