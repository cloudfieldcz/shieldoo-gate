# Multi-Upstream Indexes — Plan Index

**Source:** [`2026-06-19-multi-upstream-indexes.md`](./2026-06-19-multi-upstream-indexes.md) (design + analysis)
**Issue:** [#32](https://github.com/shieldoo/shieldoo-gate/issues/32)
**Created:** 2026-06-19
**Branch:** `feat/multi-upstream-indexes-32`

## Phases

| # | Phase | Plan File | Status | Dependencies |
|---|-------|-----------|--------|--------------|
| 1 | Config foundation (unit only — simplest) | [`…-plan-1-config.md`](./2026-06-19-multi-upstream-indexes-plan-1-config.md) | ✅ Complete | — |
| 2 | Shared resolver (unit only) | [`…-plan-2-resolver.md`](./2026-06-19-multi-upstream-indexes-plan-2-resolver.md) | ✅ Complete | Phase 1 |
| 3 | PyPI reference adapter (unit + httptest integration) | [`…-plan-3-pypi.md`](./2026-06-19-multi-upstream-indexes-plan-3-pypi.md) | ✅ Complete | Phase 1, 2 |
| 4 | **E2E scenarios (multi-index) — release gate** | [`…-plan-4-e2e.md`](./2026-06-19-multi-upstream-indexes-plan-4-e2e.md) | ✅ Complete | Phase 1, 2, 3 |
| 4b | Config migration & consistency (all repo configs → `default:` form) | [`…-plan-4b-config-migration.md`](./2026-06-19-multi-upstream-indexes-plan-4b-config-migration.md) | ✅ Complete | Phase 1 (run after Phase 3) |
| 5 | npm + NuGet | [`…-plan-5-npm-nuget.md`](./2026-06-19-multi-upstream-indexes-plan-5-npm-nuget.md) | ✅ Complete | Phase 2, 3, 4 |
| 6 | RubyGems + Go modules | [`…-plan-6-rubygems-gomod.md`](./2026-06-19-multi-upstream-indexes-plan-6-rubygems-gomod.md) | ✅ Complete | Phase 2, 3, 4, 5 |
| 7 | Maven (+ effective-POM resolver) | [`…-plan-7-maven.md`](./2026-06-19-multi-upstream-indexes-plan-7-maven.md) | ✅ Complete | Phase 2, 3, 4 |
| 8 | Docs + ADR-017 | _detailed after Phase 4_ | ✅ Complete | Phase 3, 4 |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Notes

- **Test strategy (per maintainer guidance):** Phase 1 is the simplest (unit only). Phase 2 is pure
  Go (unit only — no HTTP surface to e2e in isolation). Phase 3 adds in-process `httptest`
  integration. **Phase 4 is a dedicated E2E phase** with a docker-compose harness driving real `pip`,
  and is the canonical multi-index release gate that later ecosystem phases (5–7) extend.
- **Phases 1 and 2** can be drafted/reviewed together but Phase 2 imports the Phase 1 types, so
  build Phase 1 first.
- **Phase 3 (PyPI) is the reference implementation; Phase 4 is the reference E2E harness.** Phases
  5–7 reuse the Phase 2 resolver, mirror Phase 3's per-ecosystem download-identity recovery, and
  extend the Phase 4 harness. They are intentionally **not** detailed until the reference + harness
  land, so their plans reflect the actually-proven pattern (avoids placeholder steps the writing-plans
  skill forbids).
- Docker (`internal/adapter/docker/*`) is **deliberately untouched** per maintainer decision #4.
- **Phase 4b (config migration)** added 2026-06-19 per maintainer request: restructure **every** committed
  config (`docker/`, `examples/deploy/`, `.deploy/` prod, and the Helm chart) to the structured `default:`
  form (shape-only, no behaviour change). **No production config gets real `extra_indexes`** — prod stays a
  transparent pull-through proxy. Helm `values.yaml` + `configmap.yaml` are restructured in lockstep (no live
  prod deployment yet → no rollout risk). A new regression test loads + validates every committed config.
  `config.example.yaml` (Phase 3 T4) and `config.e2e.yaml` (Phase 4 T3) are owned by their phases.
- The "secondary-index artifact is actually scanned + cached, not bypassed" E2E assertion (Phase 4,
  extended per ecosystem in 5–7) is a non-negotiable release gate — a metadata-rewrite miss is a
  silent full scan-bypass.

## Review findings folded into the plan (2026-06-19 dev + security review)

| # | Finding | Severity | Where fixed |
|---|---------|----------|-------------|
| 1 | Scoped-breaker fall-through → public fallback (dependency confusion) | HIGH | Phase 2 `ResolveForPackage` gates on *claimed* (scope match, breaker-independent) |
| 2 | `html.Token().String()` not byte-faithful (corrupts metadata attrs) | HIGH | Phase 3 uses byte-level `href` substitution; default keeps legacy regex |
| 3 | `CheckRedirect` non-https refusal was dead code (ran after strip) | HIGH | Phase 2 evaluates refusal *before* strip, ports normalised |
| 4 | Scoped-miss audit used bare `pypi` eco, no index id | MEDIUM | Phase 3 namespaces the audit + adds index to metadata |
| 5 | Non-pythonhosted `default` mirror bypasses scanning | MEDIUM | Phase 1 WARN on non-pypi.org default; documented limitation |
| 6 | `.metadata` relay uncapped / no content-type guard per index | MEDIUM | Phase 3 caps size + guards content-type on the relay |
| 7 | Stock vs viper-weak slice hook fidelity | MEDIUM | Phase 1 adds an env→`[]string` regression test |
| 8 | `fallback`/`orDefault` helper deleted too early | MEDIUM | Phase 1/3 keep it until Phase 7 (npm/nuget/maven/rubygems/gomod still use it) |
| 9 | `encoding/json` not imported for scoped-miss audit | compile | Phase 3 Task 2 Step 0 adds the import |

**Review status:** dev + security review (full) → fixes folded → focused dev re-review **APPROVED** (three
HIGH fixes verified correct; submatch indices confirmed empirically; `SSL_CERT_FILE` CA wiring confirmed;
remaining must-fix `encoding/json` import folded in). Plans ready to execute.

## ⚠️ Execution-time security findings (Phase 3 Task 2 — per-task security review during build)

The dedicated security review of the **implemented** PyPI multi-index `/simple` rewrite surfaced a class of
**CRITICAL scan-bypass** bugs that the plan's design (byte-level `href` regex) did not anticipate. A scan
bypass here is the worst-case failure for this product: an artifact reaches `pip` **without being scanned**.
All are now fixed + regression-tested. Recorded here so the pattern is not repeated in Phases 5–7 (npm/nuget/
maven/rubygems/gomod will mirror this rewrite and MUST apply the same hardening + the same security review).

| # | Finding | Severity | Resolution |
|---|---------|----------|------------|
| S1 | **PEP 691 JSON simple API bypasses the HTML rewrite** — handler relayed client `Accept` upstream; pip ≥22.2 prefers JSON; JSON `files[].url` has no `href=` so the HTML regex matched nothing and the page was served **verbatim** → pip fetches artifacts directly (full scan bypass). | **CRITICAL** | Extra indexes are forced to an HTML `Accept`; any non-HTML 200 response **fails closed (502)**, never served. PEP 691 JSON not yet supported (documented limitation). Phase 3 commit `6cc4139`. |
| S2 | **Unquoted hrefs evaded the regex** (`href=https://evil/x`) → served un-rewritten. | HIGH | Closed by S5 (tokenizer). |
| S3 | **Embedded-quote attribute injection** — re-emitting values double-quoted let a single-quoted value containing `"` break out and inject a new un-rewritten `<a href="https://evil…">` (never host-checked). | **CRITICAL** | Closed by S5 (tokenizer parses true value boundaries). Commit `caee776`. |
| S4 | **Adjacent hrefs** (`href="x"href="y"`) — non-overlapping regex dropped the 2nd → served un-rewritten. | HIGH | Closed by S5 (tokenizer iterates every token). |
| S5 | Byte-regex is the wrong tool for a security control over adversarial HTML. | (root cause) | **Rewrite reimplemented with `golang.org/x/net/html` tokenizer** for extra indexes (default index still uses `pypiDownloadURLRe`, byte-identical). Non-anchor tokens emitted verbatim via `Raw()`; anchor href values rewritten + re-emitted via `Token().String()`. Commit `caee776`. |
| S6 | Path-traversal `..` in a rewritten suffix could escape `/ext-packages/<idx>/` scope. | MEDIUM | `..` segment in the resolved path **fails closed**. Phase 3 `/ext-packages` route (Task 3) must ALSO reject `..` (defence in depth). |
| S7 | Full upstream-header relay from a low-trust extra index (Set-Cookie/CSP/Link injection). | MEDIUM | Extra indexes relay an **allowlist** only (`Content-Type`, `ETag`, `Last-Modified`); default index unchanged. |
| S8 | Case-sensitive host comparison → uppercase host availability bug. | LOW | Host comparison lower-cased both sides. |

**Non-negotiable for Phases 5–7:** every per-ecosystem metadata rewrite is a scan-bypass surface. Each MUST
(a) fail closed on any download URL whose host is not the index/files host, (b) fail closed on non-expected
content types / formats it cannot safely rewrite, (c) use a real parser (not a byte regex) for adversarial
markup, and (d) get a dedicated security review of the *implementation*, not just the plan.

## Key settled decisions (from issue #32 thread)

| Decision | Choice |
|----------|--------|
| Resolution strategy | Ordered fallback + optional `packages` glob scoping (not merge) |
| Artifact-ID namespacing | Ecosystem-segment prefix: `eco__<index>` (default keeps bare `eco`) |
| Ordering (no scopes) | `default` first, then `extra_indexes` in config order |
| Scoped-miss | 404, **audited** |
| Docker migration to shared auth | NO — leave Docker as-is, defer |
| Typosquat vs scoped private indexes | Leave current behaviour |
| **Index `url` contract** (settled Phase 4) | An index `url` is the registry **BASE** — the gate appends the PEP 503 `/simple/<pkg>/` path itself (same as the bare `default`). Do **not** include `/simple/` in `url` (it would be doubled). An index must serve its simple API at `<url>/simple/`. Applies to `default` + every `extra_indexes[].url`; mirrored by Phases 5–7. |

## Phase 4 outcome (E2E executed — release gate PROVEN)

E2E run in the test-runner container: **S1–S5 all PASS (9/9)**. The non-negotiable release
gate **S2c is proven**: the gate logged `pypi: starting scan pipeline artifact=pypi__private:mycompany-lib:1.0:…`
→ `policy decision action=allow`, and the artifact row exists under ecosystem `pypi__private`
(scanned + cached, **not** bypassed). HTTPS fan-out to the private index works via the test-CA
bundle (`SSL_CERT_FILE`); the production https-only upstream invariant is unchanged (no insecure-http
path; no `InsecureSkipVerify`).

**Bug the E2E caught (would not have surfaced in unit/httptest):** the PyPI adapter
(`tryServeSimple`) appends `/simple/<pkg>/` to **every** index URL, but the Phase-3 docs/config
(`config.example.yaml`) had written extra-index URLs **with** their `/simple/` (or `/hexaly/`) path —
so the gate built `…/simple/simple/<pkg>/` → upstream 404 → empty simple page → **silent
non-serve** (the metadata-rewrite-miss failure mode this gate exists to catch). Resolved per the
maintainer's **base-URL contract** decision above (configs/docs fixed; product code unchanged).
This validates the plan's mandate: a metadata-rewrite/URL miss is a release-blocking bug, and only
the E2E (real fan-out over real TLS) exposes it.

## Phase 5 outcome (npm + NuGet — E2E executed, release gate PROVEN)

Full containerized E2E (strict pass): **162 passed, 0 failed.** Every multi-index release gate is
proven end-to-end against the shared HTTPS private index over the test CA:

- **npm:** `N2c` (RELEASE GATE) — `mycompany-npm-lib` packument `dist.tarball` rewritten to the gate
  origin, fetched back, scanned, and cached with an artifact row under ecosystem **`npm__private`**
  (not bypassed); `N3` scoped-miss `mycompany-ghost` → 404 + `BLOCKED` audit under
  `npm__private:mycompany-ghost`; `N4` foreign tarball host (`mycompany-npm-evil`) → **502** fail-closed
  (gate logged `SECURITY: npm packument rewrite failed … host "evil.example.net" is unroutable`).
- **NuGet:** `G2c` (RELEASE GATE) — `mycompany.nuget.lib` registration `packageContent` rewritten,
  `.nupkg` fetched, scanned, cached under **`nuget__private`**; `G3` scoped-miss `mycompany.ghost` →
  404 + `BLOCKED` audit; `G4` foreign `packageContent` host → **502** fail-closed.
- **Back-compat:** `N1`/`G1` default upstreams still serve through the gate; the existing `test_npm` /
  `test_nuget` (real `npm install` / `dotnet restore`) remain green.

Security findings folded in during execution (see commits): two CRITICAL multi-index gaps closed
(`95742bf`), the namespaced artifact row persisted under `eco__<index>` (`acd36b7`), and a
reputation-scanner false-fatal on public-registry 404 fixed (`bfb7e21`). The implementation security
review (mandate (d)) is satisfied by these fixes + the fail-closed E2E negatives.

**E2E documentation:** the whole suite — stack architecture, the harness, the full test inventory,
and an in-depth guide to how multi-upstream-index behaviour is tested — is now documented in
[`docs/development/e2e-testing.md`](../development/e2e-testing.md) (linked from `docs/index.md`).

## Phase 6 outcome (RubyGems + Go modules — E2E executed, release gate PROVEN)

Full containerized E2E (strict pass): **176 passed, 0 failed.** Both new multi-index release gates
are proven end-to-end against the shared HTTPS private index:

- **RubyGems:** `R2a` (RELEASE GATE) — `mycompany-gem` `gem_uri` rewritten to the gate origin, the
  compact-index `/info/mycompany-gem` fans out (200), the `.gem` is fetched + scanned + cached under
  **`rubygems__private`**; `R3` scoped-miss `mycompany-ghost` → 404 + `BLOCKED` audit; `R4` foreign
  `gem_uri` (`mycompany-evil`) → **502** fail-closed.
- **Go modules:** `M2a` (RELEASE GATE) — `github.com/mycompany/lib` metadata fans out, the `.zip` is
  fetched + scanned + cached under **`go__private`**; `M3` scoped-miss → 404 + `BLOCKED` audit. (No
  fail-closed case — GOPROXY metadata has no download-URL rewrite surface.)
- **Back-compat:** `R1`/`M1` default upstreams still serve through the gate; all prior PyPI/npm/NuGet
  multi-index gates + the full legacy suite remain green.

**Key simplification proven:** neither ecosystem embeds artifact download URLs in metadata (clients
construct them), so the scan chokepoint is the unconditional download route — Go modules has **no**
metadata-rewrite surface at all, RubyGems only `gem_uri`.

**Bug the E2E + security review jointly caught (now fixed):** the artifact row persisted under the
bare eco while the artifact ID was namespaced, so the release-gate API query found nothing even
though the artifact was scanned+cached. Fixed by namespacing `scanArtifact.Ecosystem` (same fix as
npm/nuget `acd36b7`). The implementation security review verdict was **Proceed** (no scan-bypass, no
metadata-path dependency confusion); two MEDIUM findings shared with npm/nuget were deferred as
follow-ups (see the [Phase 6 plan](./2026-06-19-multi-upstream-indexes-plan-6-rubygems-gomod.md#implementation-security-review-2026-06-21-mandate-d)).

## Phase 7 outcome (Maven + effective-POM resolver — E2E executed, release gate PROVEN)

Full containerized E2E (strict pass): **182 passed, 0 failed.** The Maven multi-index release gate
is proven end-to-end against the shared HTTPS private index (served under `/maven`):

- **Maven:** `MV2a` (RELEASE GATE) — `com.mycompany:lib`'s `.pom` fans out to the private index (200),
  the `.jar` is fetched through the gate + scanned + cached under **`maven__private`**; `MV3`
  scoped-miss `com.mycompany:ghost` → 404 + `BLOCKED` audit under `maven__private:com.mycompany:ghost`.
  (No fail-closed case — like Go modules, Maven embeds no download URLs in metadata, so there is no
  rewrite surface.)
- **Back-compat:** `MV1` default upstream (`org.apache.commons:commons-lang3` metadata) still serves
  through the gate; all prior PyPI/npm/NuGet/RubyGems/Go multi-index gates + the full legacy suite
  (incl. `test_license_maven`) remain green.

**Maven == gomod (plus the POM resolver):** clients construct artifact URLs from the
`groupId:artifactId:version` coordinate, so `maven-metadata.xml`/`.pom`/checksums relay **verbatim**
(no rewrite) and the scan chokepoint is the unconditional `.jar`/`.war`/`.aar`/`.zip` download route.
Resolution/scoping keys on the `groupId:artifactId` coordinate (`CanonicalPackageName` is identity for
Maven, so globs like `com.mycompany:*` match verbatim).

**The novel Maven surface — the effective-POM parent-chain resolver — now walks against the serving
index** (its base URL + per-index auth), keyed per-(baseURL,GAV) to prevent cross-index license bleed,
redirect-safe, and fail-open (best-effort license enrichment, never gates serving). The
implementation security review verdict was **Proceed** (no scan-bypass, no dependency-confusion, no
credential leak / SSRF on any of the three legs — metadata fan-out, artifact download, POM fetch).
Maven **inherits** (does not newly introduce) the two cross-adapter deferred MEDIUMs: breaker-open
claimed-name download-leg fallback to default, and unscoped-extra-index WARN-not-reject (see the
[Phase 7 plan](./2026-06-19-multi-upstream-indexes-plan-7-maven.md#inherited-deferred-findings-shared-cross-adapter-follow-ups--not-new-regressions)).

## Phase 8 outcome (Docs + ADR-017 + E2E audit — COMPLETE)

Final documentation phase. The E2E suite was **re-run once (strict pass) and audited end-to-end**
before documenting: **182 passed, 0 failed, 27 skipped**; all 22 multi-index release-gate /
scoped-miss / fail-closed assertions PASS (the 27 skips are all proxy-auth / PostgreSQL / AI-cred /
host-gated and run in the layered passes). The audit confirmed the suite is sound and internally
consistent — fixtures resolve against the Caddy routes, every `*-lib`/`*-gem` fixture embeds
`https://private-index:8443` (so the rewrite is genuinely exercised) and every `*-evil` fixture embeds
a **foreign** host (so the 502 fail-closed fires for the right reason), and the scoped-miss proof rests
on the `BLOCKED`-audit-under-`eco__<index>` row, not the (weaker) bare 404.

Audit findings (all reflected in the docs, none a product bug):

| # | Finding | Disposition |
|---|---------|-------------|
| A | `run.sh` (host) and `run_all.sh` (canonical container entrypoint) diverge — `run.sh` is a lighter subset; `test_ai_scanner` is **host-only** (it shells into the bridge via `docker exec`/`docker cp`, impossible inside the `test-runner`). | **By design.** Documented in [e2e-testing.md §3.3 / §7](../development/e2e-testing.md). The old doc's "source + call in *both* runners" guidance was corrected. |
| B | The AI-scanner's dedicated suite does **not** run in the canonical CI suite (only `version-diff` wiring + `vuln_scan_ai_ssrf` do). | Documented honestly in §3.3 / §7 (opt-in via `.env`). |
| C | `adapters.md` had **no PyPI Multi-Upstream Indexes section** despite PyPI being the reference adapter (unique `/ext-packages/<index>/` route + `files_host`). | **Fixed** — added the PyPI section (route, tokenizer rewrite, PEP 691 fail-closed, `files_host`, SSRF). |
| D | `e2e-testing.md` had a duplicated fixture-generator paragraph (omitting `gen-maven.sh`/`gen-rubygems-gomod.sh`), a phantom "S6" scenario, a false "`run.sh` sources every `test_*.sh`" claim, and stray `</content></invoke>` tool markup at EOF. | **Fixed** in the full rewrite. |
| E | `config.example.yaml` base-URL contract didn't note a base **may** include a mount path (Maven nexus). | **Fixed** — clarifying comment added. |

Deliverables: `docs/development/e2e-testing.md` fully rewritten into a complete reference (stack
architecture incl. the test-CA flow + the no-`trivy`-service clarification; per-ecosystem + per-scanner
coverage; the full scenario matrix with the why-no-fail-closed and why-scoping-is-required rationale; a
worked recipe for adding a scenario; the two deferred MEDIUMs). `docs/adr/ADR-017` committed;
`docs/index.md` ADR list bumped to ADR-017; `adapters.md` + `config.example.yaml` consistency-checked.
