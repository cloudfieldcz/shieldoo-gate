# ADR-017: Multi-Upstream Indexes via Ordered Fallback + Name Scoping (non-Docker ecosystems)

Date: 2026-06-21

## Status

Accepted (issue [#32](https://github.com/shieldoo/shieldoo-gate/issues/32); implemented in Phases 1–7 — see the
[plan index](../plans/2026-06-19-multi-upstream-indexes-plan-index.md) and
[design](../plans/2026-06-19-multi-upstream-indexes.md))

## Context

Each non-Docker ecosystem upstream (`upstreams.pypi`, `npm`, `nuget`, `maven`, `rubygems`, `gomod`) was a
single string. A private/secondary index (a vendor index, an internal Nexus/Artifactory/GOPROXY, …) could
not be served **through the gate** alongside the public default. The only client-side workaround
(`pip --extra-index-url`, a second `npm` registry, a Maven `<mirror>` bypass, …) routes around the gate
entirely — **no scan, no policy, no cache** — and introduces a dependency-confusion risk (clients merge
versions across indexes and can pick an attacker's public package over the intended private one).

Docker already solves the analogous problem with `default_registry` + `allowed_registries`, but its model
does **not** transfer: Docker routes **per-request** because the registry host is embedded in the image ref
(`ghcr.io/org/img`). Every other ecosystem sends a **bare package name / coordinate** with no host hint, so
per-package routing the Docker way is impossible. Multiplexing must be either *fan-out + merge* or *ordered
fallback*.

## Decision

### 1. Resolution: ordered fallback + optional `packages` glob scoping (not merge)

A package is served from **exactly one** index. Routing for a name/coordinate `<pkg>`:

1. If any index's `packages` globs match (the name is **claimed**) → query **only** the claiming indexes,
   in config order; first hit serves; **none has it → 404, no public fallback** (the scoped-miss is
   **audited**). "Claimed" is decided **independently of the circuit breaker**: if every claiming index has
   an open breaker the result is an empty list → still a 404, never a public fallback (the
   dependency-confusion guard — a claimed namespace is never silently shadowed by public).
2. Otherwise → `default` first, then unscoped `extra_indexes` in config order (breaker-open indexes
   skipped); first hit wins.

Fan-out + merge was rejected: merge semantics differ per protocol and it **replicates** clients'
"highest version across indexes" behaviour, which is the dependency-confusion vector. Ordered fallback
generalises across all ecosystems **and** is itself a security feature.

Globs match with `filepath.Match` (linear, no ReDoS) against the **canonical** package name; patterns are
validated at config load (hard-fail on empty / `*`-only). An authenticated index with no `packages` scope
gets a startup WARN + metric (an authenticated index that can still be shadowed by public is almost always
a misconfig).

### 2. Artifact-ID namespacing: `eco__<index>` segment prefix

The index dimension folds into the **ecosystem segment** of the artifact ID, keeping the 4-segment
`eco:name:version:filename` structure. The default index keeps the bare eco (`pypi`); an extra index `corp`
becomes `pypi__corp`. `__` is chosen because it is valid under the cache layer's `validNameRe`
(`^[a-zA-Z0-9._\-]+$`) and index names are validated to `^[a-z0-9-]+$`, so the boundary is unambiguous and
**no cache backend** (local/S3/Azure/GCS) needs changes — they already isolate on the eco segment. The
**scanner `Ecosystem` field also carries the namespaced segment** so the persisted artifact row + cache
isolate per index (the release-gate query keys on `?ecosystem=eco__<index>`).

### 3. Metadata rewrite is per-ecosystem and **fail-closed** — never a byte regex over adversarial markup

A metadata-rewrite miss is a **silent full scan-bypass** (an artifact reaches the client without scanning),
the product's worst-case failure. So per ecosystem:

- **PyPI** (`/simple/`) — extra indexes rewrite anchor `href`s with a real `golang.org/x/net/html` tokenizer
  (never a byte regex); an absolute URL to a foreign host **fails closed (502)**; PEP 691 JSON is forced to
  HTML and any non-HTML 200 fails closed; `/ext-packages/<index>/` carries index identity on the download
  leg (SSRF-validated). The default index keeps its byte-identical legacy regex.
- **npm** (`dist.tarball`) / **NuGet** (`packageContent`) — JSON-aware rewrite that fails closed if a
  download URL's host is not the index/files host (NuGet additionally pins the `/v3-flatcontainer/` path
  shape).
- **RubyGems** — only `gem_uri` is rewritten (fail-closed); `/info/{name}` + version metadata relay verbatim.
- **Go modules** and **Maven** — **no metadata rewrite surface at all**: clients construct download URLs
  from the module path / `groupId:artifactId:version` coordinate, so metadata is relayed **verbatim**
  (size-capped, header allowlist for extra indexes). The unconditional download route is the scan chokepoint.

### 4. Carrying index identity to the stateless download leg — per-ecosystem

- **PyPI** uses a dedicated `/ext-packages/<index>/<path>` route (validated → `FilesHostFor` lookup → auth).
- **npm / NuGet / RubyGems / Go / Maven** re-run `ResolveForPackage(<name|coordinate>)` in the download
  handler (resolution is deterministic per package), recovering the serving index, namespacing the artifact,
  and attaching per-index auth.

### 5. Shared SSRF + credential-leak controls

A single `adapter.UpstreamResolver` (the non-Docker analogue of `RegistryResolver`) provides
`ResolveForPackage`, env-only `AuthHeader` (never the client `Authorization`), `FilesHostFor` (fail-closed
on a forged/unknown index name **before** any URL is built), a short per-index probe timeout + circuit
breaker, and a **redirect-safe HTTP client** whose `CheckRedirect` (a) refuses a credentialed redirect to a
non-https target *before* stripping, (b) strips `Authorization` on any host **or scheme** change (default
ports normalised), and (c) caps redirect depth. Config validation enforces `https://`-only absolute URLs
with no userinfo; `files_host` is PyPI-only and rejected elsewhere.

### 6. Maven effective-POM resolver walks against the serving index

Maven's parent-POM license-enrichment walk is **pinned to the serving index** (its base URL + per-index
auth), cache-keyed per-(baseURL,GAV) to prevent cross-index license bleed, redirect-safe, and **fail-open**
(it never gates serving — a parent absent from the index simply yields fewer enriched licenses). It never
fetches an artifact (only `.pom`s) and a malicious `<parent>` can only change the path under the pinned host,
never the host itself.

### 7. Docker is deliberately untouched

Docker keeps its existing `default_registry` + `allowed_registries` per-request routing. Migrating it to the
shared `UpstreamAuth` is explicitly deferred (maintainer decision #4).

## Consequences

- A private/secondary index is served **through** the gate for every non-Docker ecosystem: scanned, policy-
  evaluated, cached, namespaced `eco__<index>` — no client-side gate bypass, and dependency confusion is
  structurally prevented (a name is served from exactly one index; a claimed-but-absent name is a hard 404).
- Back-compat is preserved: a bare-string upstream (and `SGW_UPSTREAMS_*` env override) decodes to
  `UpstreamSet{Default}` via a viper DecodeHook + explicit `BindEnv`; default-only behaviour is
  byte-/status-identical to the pre-feature gate on the served path.
- Each per-ecosystem rewrite is a scan-bypass surface and got a dedicated **implementation** security review
  (not just a plan review). The non-negotiable release gate — "a secondary-index artifact is actually
  scanned + cached, not bypassed" — is proven end-to-end per ecosystem in the docker-compose E2E harness
  (PyPI/npm/NuGet/RubyGems/Go/Maven, all green).
- **Limitations:** for the flat-coordinate ecosystems (npm/nuget/rubygems/gomod/maven) extra indexes **must
  be `packages`-scoped** (the download leg recovers the index by re-resolution; an unscoped extra index
  cannot be recovered → unsupported). Whole-index enumeration (e.g. RubyGems `/versions`, the PyPI root
  `/simple/`) is default-only. Two cross-adapter MEDIUM hardening items are tracked as follow-ups: a
  breaker-open claimed-name download leg falls back to the default (still scanned, but could fetch a public
  package of the same name during a private-index outage), and an unscoped extra index is currently WARNed
  rather than rejected at config load.

## References

- Design + analysis: [`2026-06-19-multi-upstream-indexes.md`](../plans/2026-06-19-multi-upstream-indexes.md)
- Plan index (per-phase plans + execution-time security findings):
  [`2026-06-19-multi-upstream-indexes-plan-index.md`](../plans/2026-06-19-multi-upstream-indexes-plan-index.md)
- Adapter behaviour + per-ecosystem multi-index sections: [`adapters.md`](../adapters.md)
- E2E scenario matrix: [`development/e2e-testing.md`](../development/e2e-testing.md)
- Related: [ADR-001](ADR-001-project-identification-via-basic-auth.md) (Basic-auth project identity),
  [ADR-003](ADR-003-pypi-canonical-package-names.md) (canonical names, reused for glob scoping).
