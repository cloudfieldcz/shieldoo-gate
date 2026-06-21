# Multi-Upstream Indexes (all non-Docker ecosystems) — Design & Analysis

**Date:** 2026-06-19
**Status:** Design settled — see [plan index](./2026-06-19-multi-upstream-indexes-plan-index.md) for implementation
**Source:** GitHub issue [#32](https://github.com/shieldoo/shieldoo-gate/issues/32) (PyPI multi-index → generalised to all non-Docker ecosystems)

## Problem

`upstreams.pypi` (and `npm`/`nuget`/`maven`/`rubygems`/`gomod`) is a single string. A private/secondary
index (e.g. a vendor index like Hexaly at `https://pip.hexaly.com/hexaly/`) cannot be served
through the gate alongside public PyPI. The only client-side workaround (`pip --extra-index-url`)
**bypasses the gate entirely** (no scan, no policy, no cache) and introduces a dependency-confusion
risk (pip picks the highest version across indexes). Docker already solves the analogous problem
with `default_registry` + `allowed_registries`, but its model does not transfer (see below).

## Why Docker's model doesn't transfer

Docker routes **per-request** because the registry host is embedded in the image ref
(`ghcr.io/org/img`) and `RegistryResolver.Resolve()` (`internal/adapter/docker/registry.go:49`)
parses it. Every other ecosystem sends a **bare package name** with no host hint, so we cannot route
per-package the same way. Multiplexing must be either *fan-out + merge* or *ordered fallback*.

Second complication (PyPI-specific): the download leg is **stateless**. `/packages/*`
(`internal/adapter/pypi/pypi.go:149`) hardcodes the CDN
(`const pypiFilesHost = "https://files.pythonhosted.org"`) and rewrites metadata URLs with a fixed
regex (`pypiDownloadURLRe`, `pypi.go:537`). A different index whose files live elsewhere won't match,
and the download handler has lost all knowledge of *which* index a given `/packages/...` path
belongs to.

## Resolution strategy — ordered fallback + optional name scoping

| Strategy | Generalises? | Dependency-confusion safety | Complexity |
|----------|--------------|------------------------------|------------|
| Fan-out + merge | No — merge semantics differ per protocol | Replicates pip's "highest version across indexes" → **unsafe** | High |
| **Ordered fallback** (first index that has the package serves *all* its versions) | Yes — uniform | **Safer than pip** — a package is served from exactly one index | Low–Med |

Ordered fallback is the only strategy that generalises **and** it is itself a security feature:
"first index that has the package owns all its versions" eliminates pip's cross-index version merge.

**Name scoping** closes the ordering trap. Pure ordering can't satisfy both real cases at once:
- **Hexaly** — vendor pkg exists *only* on the vendor index → public-first, 404, fall through. Fine.
- **Private `mycompany-*`** — public-first lets an attacker's `mycompany-secret` on public PyPI win.
  Needs private-first, but then every lookup hits the private index.

Optional per-index `packages` glob list resolves both.

### Routing for package `<pkg>`

1. If any index's `packages` patterns match (the name is **claimed**) → query **only** those
   matching indexes (in config order); first hit serves; **none has it → 404, no fallback** (a
   claimed namespace is never silently shadowed by public). The scoped-miss 404 is **audited**.
   **Critical:** "claimed" is decided independently of the circuit breaker. If every claiming index
   has an **open breaker**, the result is an empty list → still a scoped miss (**404**), never a
   public fallback. (An earlier draft gated on the breaker-filtered list being non-empty, which
   would have fallen through to public when the private index was down — a dependency-confusion
   regression. Fixed.)
2. Otherwise (name not claimed) → `default` first, then unscoped `extra_indexes` in config order
   (breaker-open indexes skipped); first hit wins.

Match with `filepath.Match` (glob, linear — no ReDoS), canonicalise the package name *before*
matching, validate every pattern at config load (hard-fail on empty / `*`-only), and emit a startup
**WARN + metric** for any index that has `auth` but no `packages` scope (an authenticated index that
can still be shadowed by public is almost always a misconfig).

## Config schema (back-compatible)

```yaml
upstreams:
  pypi:
    default: "https://pypi.org"              # bare string still accepted (back-compat)
    extra_indexes:
      - name: "hexaly"                        # unscoped fallback index
        url: "https://pip.hexaly.com/hexaly/"
      - name: "corp"
        url: "https://pkgs.internal.example.com/simple/"
        packages: ["mycompany-*", "acme-*"]   # pinned namespace
        files_host: "https://files.internal.example.com/"   # PyPI only
        auth:
          type: "basic"                       # "bearer" | "basic"
          token_env: "SGW_CORP_INDEX_TOKEN"   # env var only — never plaintext
```

A bare string (`pypi: "https://pypi.org"`) decodes to `UpstreamSet{Default: "https://pypi.org"}`.

## Maintainer decisions (issue #32 thread)

1. **Artifact-ID namespacing:** use the **ecosystem-segment prefix**. The index dimension folds into
   the first (eco) segment of the artifact ID, keeping the 4-segment `eco:name:version:filename`
   structure. The default index keeps the bare eco (`pypi`); an extra index `corp` becomes
   `pypi__corp` (separator chosen from the cache's `validNameRe` allowed set `[a-zA-Z0-9._\-]`, see
   below). This requires **zero** changes to `parseArtifactID` / `validateName` / `artifactDir` /
   `Delete` and the S3/Azure/GCS key derivations — they already isolate on disk by the eco segment.
2. **Ordering with no scopes:** `default` first, then `extra_indexes` in config order.
3. **Scoped-miss 404:** yes, **audit it** (a silently-404'd private package masks a
   compromised/unreachable private index).
4. **Docker → shared `UpstreamAuth` migration:** **NO** — leave Docker untouched, do it later.
5. **Typosquat pre-scan vs scoped private indexes:** **leave** current behaviour as-is.

### Artifact-ID separator decision (detail)

`internal/cache/local/local.go` validates each ID segment against
`validNameRe = ^[a-zA-Z0-9._\-]+$` and rejects `/`, `\`, `..`. Of the allowed separators, `__`
(double underscore) is chosen because:
- It is valid in `validNameRe` (so no cache-layer change is needed across local/S3/Azure/GCS).
- It is reserved: ecosystem identifiers (`pypi`, `npm`, …) are fixed literals that never contain
  `__`, so `pypi__corp` is unambiguous and parseable back to `(eco=pypi, index=corp)`.
- Index `name` values are validated at config load to `^[a-z0-9-]+$` (no underscores), so the `__`
  boundary can never be ambiguous.

Helper: `adapter.NamespacedEcosystem(eco, indexName) string` →
`eco` when `indexName == ""` (default), else `eco + "__" + indexName`. The reverse split is only
needed where audit/SBOM history wants the bare eco; the cache treats the whole namespaced eco as
opaque.

## Architecture

### Shared config types (`internal/config/config.go`)

```go
type UpstreamSet struct {
	Default      string          `mapstructure:"default"`
	ExtraIndexes []UpstreamIndex `mapstructure:"extra_indexes"`
}
type UpstreamIndex struct {
	Name      string        `mapstructure:"name"`        // stable id: artifact namespacing + download routing
	URL       string        `mapstructure:"url"`
	FilesHost string        `mapstructure:"files_host"`  // PyPI only (separate file CDN)
	Packages  []string      `mapstructure:"packages"`    // optional glob scope
	Auth      *UpstreamAuth `mapstructure:"auth"`
}
type UpstreamAuth struct {       // generalised analogue of DockerRegistryAuth (Docker stays separate)
	Type     string `mapstructure:"type"`       // "bearer" | "basic" — validated strictly, no default
	TokenEnv string `mapstructure:"token_env"`  // env var name; never plaintext
}
```

`UpstreamsConfig` fields `pypi`/`npm`/`nuget`/`maven`/`rubygems`/`gomod` change `string → UpstreamSet`.
Docker fields untouched.

### Back-compat decode hook

`Load` calls `v.Unmarshal(&cfg)` with **no DecodeHook today** (`config.go:694`). Add a
`string → UpstreamSet{Default}` decode hook via viper's `DecodeHook` using
`github.com/go-viper/mapstructure/v2` (viper's vendored mapstructure — *not* `mitchellh/mapstructure`).
`SGW_UPSTREAMS_PYPI=...` env override into a now-struct field is the highest back-compat risk:
`AutomaticEnv` does not reliably populate a nested struct from a scalar env-only key, so add an
explicit `BindEnv("upstreams.pypi", …)` per ecosystem + a dedicated test.

### Shared resolver (`internal/adapter/upstream_set.go`)

The non-Docker analogue of `RegistryResolver` (the `adapter.Adapter` interface needs **no** change —
adapters gain a resolver field):
- `ResolveForPackage(canonicalPkg string) []ResolvedIndex` — ordered list to try, applying the
  scoping rules. Each `ResolvedIndex` carries `{Name, URL, FilesHost, auth}`.
- `AuthHeader(index) string` — reads `token_env`, formats `Bearer`/`Basic`; never forwards the
  client `Authorization` (which could be the global super-token).
- `FilesHostFor(indexName) (host string, ok bool)` — server-side download-host lookup (SSRF control).
- An `*http.Client` with an **explicit `CheckRedirect`** that, in this order: (1) refuses a
  credentialed redirect to a non-`https` target **regardless of host** (so the refusal is not dead
  code — it must run *before* the strip), (2) strips `Authorization` on any host or scheme change
  (comparing hosts with default ports normalised), and (3) caps redirect depth.
- Short **per-index probe timeout** + lightweight circuit breaker, distinct from the 5-minute
  artifact-download timeout, so a slow/dead private index can't stall fallback for every lookup.

### SSRF — one consolidated, fail-closed invariant

The download leg stays SSRF-safe: validate `<index-name>` against a strict regex → `FilesHostFor`
returns 404 **before any URL is built** on unknown name → config-time validation that every
`url`/`files_host` is an `https://` absolute URL with a host and **no userinfo** (reject `file://`,
`http://`). Test: "forged/unknown index name → 404, no upstream request."

### Metadata rewrite — byte-level, fail-closed (NOT an HTML reserializer)

The simple-page rewrite operates on the **raw response bytes**, substituting only the matched
anchor-`href` values; every other byte is preserved. (An HTML tokenize→reserialize round-trip via
`x/net/html` was rejected in review: `Token()` unescapes and `Token.String()` re-escapes/reorders
attributes, which would perturb `data-requires-python` / `data-dist-info-metadata` and break the
"byte-identical default index" guarantee.) Concretely:
- **Default index** keeps the existing targeted regex (`pypiDownloadURLRe` → `/packages/`) — **byte
  identical** to today. Limitation: it only rewrites `files.pythonhosted.org`; a non-PyPI mirror set
  as `default` whose files live elsewhere is **not** rewritten and is therefore unsupported for
  scanning — config load WARNs on a non-`pypi.org` default, and docs state the limitation.
- **Extra indexes** use a byte-level `href` substitution: each anchor `href` is resolved against the
  simple-page URL; an absolute/relative URL whose host is the index's files host (or index host) is
  rewritten to `/ext-packages/<index>/<path>`; an absolute URL to a **foreign** host **fails closed**
  (502 — serving it would let pip fetch the artifact directly, bypassing the scan). Relative hrefs
  resolve onto the index host and are likewise rewritten, so they cannot accidentally route to the
  gate's default `/packages/` handler.

### Carrying index identity to the download leg — per-ecosystem

- **PyPI** — `/packages/*` is opaque (no package name). Extra-index files use a **separate** route
  `/ext-packages/<index>/<orig>` (not a `/packages/` sub-path, so it can never collide with PyPI CDN
  path shapes); the default index keeps today's un-prefixed `/packages/` path for back-compat. The
  download handler validates `<index>` (SSRF), looks up `FilesHostFor`, and attaches auth.
- **npm / NuGet / Maven / RubyGems / Go** — the download route already carries the package id, so
  recover index identity by **re-running `ResolveForPackage(pkg)`** in the download handler (fallback
  is deterministic per package). No path prefix; `files_host` is irrelevant (files share the metadata
  origin; these rewrite to `r.Host`).

### Root `/simple/` (PyPI)

Serve `default`'s index only (don't merge huge root pages; pip queries per-package). Extra-index
packages still resolve on direct per-package lookup. Documented limitation.

## Affected files

**New:** `internal/adapter/upstream_set.go` (+ tests); config decode hook; per-ecosystem `examples/`;
`tests/e2e-shell/` second-index cases; `docs/adr/ADR-017-multi-upstream-indexes.md`.

**Modified:** `internal/config/config.go` (types, `Load` DecodeHook + BindEnv, `Validate` rules);
`cmd/shieldoo-gate/main.go:495-530` (pass `UpstreamSet` instead of `fallback()` string — note maven
also wires `effectivepom.NewResolver`, which must learn the resolved index); `internal/adapter/pypi/*`
(reference impl); `internal/adapter/{npm,nuget,maven,rubygems,gomod}/*`; `docs/`; `config.example.yaml`.

**Unchanged (deliberately):** `internal/adapter/docker/*`; scan/policy/cache pipeline (index-agnostic —
only the artifact-ID input changes); cache backends' parse/validate/key logic (the namespaced eco
segment is opaque to them).

## Phasing

One module per phase (per CLAUDE.md task granularity). Per maintainer guidance, **Phase 1 stays the
simplest (unit only); E2E is broken out into its own dedicated phase** that grows in complexity:

1. **Config foundation** — shared types, string→struct DecodeHook + BindEnv, Validate rules. No
   behaviour change (default-only == today). **Unit tests only** (simplest phase).
2. **Shared resolver** — `upstream_set.go`: ordered fallback + scoping (scoped-breaker → 404, never
   public fallback), env-var auth, files-host lookup, explicit ordered redirect auth-strip, per-index
   probe timeout/breaker. **Pure unit tests** (no HTTP surface to e2e in isolation).
3. **PyPI reference adapter** — resolver wiring, byte-level fail-closed rewrite, `/ext-packages/<index>/`
   download routing, per-index `files_host`, artifact-ID namespacing, scoped-miss audit. **Unit +
   in-process integration (`httptest`) tests**; example project.
4. **E2E scenarios (multi-index)** — dedicated docker-compose E2E harness driving real `pip` against
   the gate, validating the Phase 1/2/3 behaviour end-to-end: back-compat (string config), default-only,
   multi-index fan-out, scoped private index, scoped-miss 404, **auth'd private-index artifact scanned +
   cached (not bypassed)**, scan-bypass-prevention, env-var auth. This is the **release gate** and the
   reusable harness later ecosystem phases extend.
5. **npm + NuGet** — index recovery via re-resolution; per-protocol metadata rewrite. Examples + e2e.
6. **RubyGems + Go modules** — path-based ordered fallback. Examples + e2e.
7. **Maven** — adapter + effective-POM parent-chain resolver resolves against the serving index. The
   effective-POM resolver (`main.go` double-wires `mavenUpstream`) must learn the resolved index.
8. **Docs + ADR** — finalise docs, ADR-017, `config.example.yaml`.

Phases 5–8 are detailed once the shared foundation (1–2), the PyPI reference (3), and the E2E harness
(4) land, because they reuse the resolver from Phase 2, mirror the per-ecosystem pattern proven in
Phase 3, and extend the harness from Phase 4.

Each phase gate: `make build && make lint && make test`. The **"secondary-index artifact is actually
scanned + cached, not bypassed"** assertion (Phase 4, extended per ecosystem in 5–7) is a
non-negotiable release gate — a metadata-rewrite miss is a silent full scan-bypass.

## Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Dependency confusion | Critical | Ordered fallback + `packages` scoping; scoped-miss → 404 (no public fallback); WARN+metric on auth-without-scope |
| SSRF via download path | High | Server-side `FilesHostFor`, fail-closed on unknown index, https-only config URLs, forged-name→404 test |
| Private token leaks on redirect | High | Explicit `CheckRedirect` stripping `Authorization` on host **or scheme** change; refuse non-https credentialed redirects; env-only tokens, never logged |
| Metadata-rewrite miss = silent scan bypass | High | Per-index rewrite against configured host; e2e proves secondary-index artifact was scanned+cached |
| Back-compat break (string config / `SGW_*` env) | High | DecodeHook + `BindEnv`; dedicated tests |
| Fallback latency / slow private index | Medium | Scoping short-circuits; short per-index probe timeout + circuit breaker; cache hits skip resolution |
| `type` typo silently sends wrong scheme | Medium | Strict `bearer\|basic` validation, fail closed |
| Maven effective-POM resolver single-upstream | Medium | Phase 6: resolver resolves against serving index |
