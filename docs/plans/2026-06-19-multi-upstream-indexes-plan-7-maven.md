# Multi-Upstream Indexes — Phase 7: Maven (+ effective-POM resolver)

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run E2E redirected to a log file, then tail it (per the repo's E2E-via-logfile convention).

**Goal:** Extend the proven Phase 2 resolver + Phase 6 (gomod) reference pattern to the **Maven** adapter: fan per-coordinate metadata/POM/checksum requests across the default + extra indexes (ordered fallback + glob scoping on `groupId:artifactId`), recover the serving index on the artifact (`.jar`/`.war`/`.aar`/`.zip`) download leg by **re-resolving the coordinate**, namespace artifact IDs via `eco__<index>`, carry per-index env-var auth (redirect-safe), audit scoped-misses, and — the Maven-specific complication — make the **effective-POM parent-chain resolver walk against the same serving index** (URL + auth) instead of a single hardcoded upstream. Extend the Phase 4/5/6 docker-compose E2E harness with a private Maven artifact and prove the non-negotiable release gate: **a secondary-index artifact is scanned + cached, not bypassed.**

**Architecture (Maven == gomod, plus the POM resolver):** Maven, like Go modules and unlike npm/NuGet/PyPI, **embeds no artifact download URLs in its metadata** — Maven clients (`mvn`, Gradle) construct artifact URLs themselves from `groupId/artifactId/version` against the configured repository base. So Maven has **no metadata-rewrite surface**: `maven-metadata.xml`, `.pom`, and checksums (`.sha1`/`.md5`/`.sha256`/`.asc`) are relayed **verbatim** (size-capped); the scan chokepoint is the unconditional artifact-download route, which already scans every `.jar`/`.war`/`.aar`/`.zip` regardless of index. The only multi-index work on the metadata legs is *which* index is queried (resolve by coordinate) + the scoped-miss 404/audit. The one piece with no gomod analogue is the **effective-POM resolver** (`internal/maven/effectivepom`), a best-effort license-enrichment walk over the parent POM chain that today fetches from a single hardcoded `upstreamURL`; it must learn the serving index so a private artifact's parents are fetched from the private index (with its auth), not silently from public.

**Tech Stack:** Go 1.25, `github.com/go-chi/chi/v5`, the Phase 2 `adapter.UpstreamResolver`, `net/http/httptest` (unit/integration), docker-compose + Caddy + the test CA (E2E).

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

---

## Security mandate (carried from the plan index — non-negotiable for this phase)

Every per-ecosystem metadata path is a potential scan-bypass surface. Maven MUST:

- **(a)** route every artifact **download** (`.jar`/`.war`/`.aar`/`.zip`) through the gate's unconditional scanning download route (it already does — the client constructs `…/{ver}/{file}.jar` against the gate); the download leg MUST recover the **correct** serving index by re-resolving the coordinate so a scoped private artifact is fetched from its private index (with its auth) and stored under `maven__<index>` (never silently fetched from public);
- **(b)** a **claimed-namespace miss** on a per-coordinate metadata/POM request returns 404 (no public fallback) and is audited under `maven__<firstClaimant>` — the dependency-confusion guard (Phase 2 `ResolveForPackage` already returns only claiming indexes for a claimed name);
- **(c)** the **effective-POM resolver** must NOT leak per-index credentials on a cross-host redirect (use the redirect-safe client) and must not introduce a metadata-path download-URL surface (it never fetches `.jar`s — only `.pom`s for license text, which is best-effort/fail-open and never gates serving);
- **(d)** get a dedicated **security review of the implementation** (security-code-review skill), not just this plan.

Default-index behaviour stays **status-identical** to today on the served (200) path (verbatim relay of `maven-metadata.xml`/`.pom`/checksums; unchanged scan→policy→serve for artifacts). Two deliberate changes, both safe because `mvn`/Gradle key on the **status code**, not the 404 body:
1. A per-coordinate **404** from the default index now flows through the fan-out's scoped-miss tail and returns a small `"not found"` body instead of relaying the upstream's 404 body.
2. A per-coordinate **non-200/non-404** (e.g. a transient upstream 500) is treated as a probe error → the fan-out tries the next index, then 404s, instead of relaying the 5xx. (Recorded by the dev review; matches the gomod fan-out tail.)

---

## Settled design decisions (Maven-specific, consistent with Phases 1–6)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Resolution / scoping key** | `groupId:artifactId` (the existing typosquat `coordName`) | `scanner.CanonicalPackageName` is **identity** for Maven (`internal/scanner/canonicalname.go:30`), so globs match the coordinate verbatim. Admins write `packages: ["com.mycompany:*"]`. The colon form matches how Maven users think and is already the typosquat coordinate. |
| **Extra indexes MUST be `packages`-scoped** (mirrors gomod S5) | Documented hard limitation | The flat-coordinate download leg recovers the serving index by re-resolving the coordinate; an *unscoped* extra index cannot be recovered on download → its artifact would be re-fetched from the default (content substitution). Unscoped extra indexes are unsupported for Maven. |
| **`maven-metadata.xml` coordinate parse** | Best-effort: artifact-level `g/a/maven-metadata.xml` parsed exactly; version-level `g/a/{ver}/maven-metadata.xml` (SNAPSHOTs) detected by a `looksLikeVersion` heuristic and the version segment dropped | The actual scan gate is the `.jar` download (always exact); metadata is only version *discovery*, so a heuristic miss on an exotic SNAPSHOT path mis-resolves a *version listing*, never bypasses a scan. Documented. |
| **Effective-POM resolver index** | Pin the **entire parent-chain walk to the serving index** (URL + auth), not per-parent re-resolution | The resolver is best-effort license enrichment, **fail-open**, never a gate. Per-parent re-resolution would add a dependency-confusion surface (a private parent GAV could be shadowed by public). A private artifact's parents live in its private index (or the private index proxies Central). A pinned walk that 404s on an absent public parent simply yields fewer licenses — acceptable. |
| **POM cache key** | `(baseURL, GAV)` not `GAV` alone | Prevents cross-index license bleed: a public parent's empty/404 result cached under a private walk must not satisfy a later public walk for the same GAV (and vice-versa). Low-churn change to `pomCache`. |
| **`files_host`** | Rejected for Maven (PyPI-only; enforced at config load — `internal/config/config_upstreams.go:130`) | Maven artifacts share the metadata origin; no separate file CDN concept. |
| **Artifact-ID namespacing** | `maven__<index>:groupId:artifactId:version` (default keeps bare `maven:…`) | Same `eco__<index>` rule as every other ecosystem; the scanner `Ecosystem` field also carries the namespaced segment so the persisted artifact row + cache isolate per index (the npm/nuget/gomod `acd36b7` release-gate fix). |
| **Typosquat pre-scan** | Unchanged — keeps bare `maven:` eco, runs on the download leg only | Typosquat is name-based and pre-resolution; matches gomod (`go:modulePath:*`). |

---

## File structure

- **Modify:** `cmd/shieldoo-gate/main.go` — pass `cfg.Upstreams.Maven` (UpstreamSet) to the Maven adapter; give the effective-POM resolver a **redirect-safe** client; drop the `mavenUpstream`-string double-wire's adapter leg.
- **Modify:** `internal/adapter/maven/maven.go` — constructor takes `config.UpstreamSet`; `resolver` field; coordinate helpers; pass-through + metadata fan-out; download index recovery + namespaced IDs + auth; scoped-miss audit; thread the serving index into the effective-POM call.
- **Modify:** `internal/adapter/maven/maven_test.go` + `maven_typosquat_test.go` — migrate the `NewMavenAdapter(...)` setup to the new constructor signature.
- **Create:** `internal/adapter/maven/maven_multi_index_test.go` — black-box (`package maven_test`) multi-index unit/integration tests.
- **Modify:** `internal/maven/effectivepom/resolver.go` — add `ResolveFrom(ctx, c, baseURL, authHeader)`; keep `Resolve(ctx, c)` as a back-compat wrapper; per-(baseURL,GAV) cache key; auth header on POM fetch.
- **Modify:** `internal/maven/effectivepom/cache.go` — cache keyed by an explicit string (`baseURL|GAV`) instead of bare `Coords.String()`.
- **Modify:** `internal/maven/effectivepom/resolver_test.go` — cover the new method + per-index key, and update the existing `pomCache.get/put` calls (they live here, **not** in a `cache_test.go` — that file does not exist) to pass a string key.
- **Modify:** `config.example.yaml` — `maven` multi-index schema block.
- **Create:** `examples/maven-private-repo/README.md`, `examples/maven-private-repo/settings.xml.example`.
- **Modify (config migration):** `docker/config.yaml`, `examples/deploy/config.yaml`, `.deploy/config.yaml` (skip if absent), Helm `values.yaml` + `configmap.yaml` — restructure `maven` to the `default:` form (shape-only; no prod `extra_indexes`).
- **Create:** `tests/e2e-shell/fixtures/private-index/gen-maven.sh` + committed `www/maven/` subtree; `tests/e2e-shell/test_maven_multi_index.sh`.
- **Modify:** `tests/e2e-shell/config.e2e.yaml` (wire maven multi-index), `tests/e2e-shell/fixtures/private-index/Caddyfile` (serve the maven tree if not already covered), `tests/e2e-shell/run.sh` + `run_all.sh` (register the new test).
- **Modify:** `docs/adapters.md` — Maven "Multi-Upstream Indexes" section; `docs/development/e2e-testing.md` — extend the scenario matrix.

Depends on Phase 1 (`config.UpstreamSet`), Phase 2 (`adapter.UpstreamResolver`), Phase 3 (reference pattern), Phase 4 (E2E harness), Phase 6 (gomod download-leg + verbatim-relay fan-out pattern). The final ADR-017 + docs consolidation is **Phase 8**, not this phase.

---

## Task 1: Maven — resolver wiring (default-only behaviour unchanged)

**Files:**
- Modify: `internal/adapter/maven/maven.go` (struct ~43-53, constructor ~69-88)
- Modify: `cmd/shieldoo-gate/main.go` (~499, ~523, ~526)
- Test: `internal/adapter/maven/maven_test.go`, `internal/adapter/maven/maven_typosquat_test.go` (setup)

- [ ] **Step 1: Migrate the test setup to the new constructor (failing)**

In `internal/adapter/maven/maven_test.go` **and** `internal/adapter/maven/maven_typosquat_test.go`, find every `NewMavenAdapter(` call and change the upstream argument from a bare string to a `config.UpstreamSet`. The constructor keeps the trailing `pomResolver` argument. Example:

```go
a := maven.NewMavenAdapter(db, cacheStore, scanEngine, policyEngine,
	config.UpstreamSet{Default: upstream.URL}, nil)
```

(Add `"github.com/cloudfieldcz/shieldoo-gate/internal/config"` to the test imports if not present. Use `nil` for the `pomResolver` arg wherever the existing tests already pass `nil`; where a test passes a real resolver, leave that argument unchanged.)

Run: `go test ./internal/adapter/maven/ -count=1` → FAIL to compile (constructor still wants a string).

- [ ] **Step 2: Change the struct + constructor**

In `internal/adapter/maven/maven.go`, add `resolver` and accept an `UpstreamSet`. Replace the struct field `upstream string` block and the constructor:

```go
// MavenAdapter proxies Maven repository HTTP layout with artifact scanning.
type MavenAdapter struct {
	db           *config.GateDB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstream     string // default index base (back-compat; == resolver default)
	resolver     *adapter.UpstreamResolver
	router       http.Handler
	httpClient   *http.Client
	pomResolver  *effectivepom.Resolver // nil when effective-POM resolution is disabled
}

// NewMavenAdapter creates and wires a MavenAdapter. The pomResolver may be nil
// when effective-POM parent chain resolution is disabled.
func NewMavenAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreams config.UpstreamSet,
	pomResolver *effectivepom.Resolver,
) *MavenAdapter {
	defaultURL := upstreams.DefaultOr("https://repo1.maven.org/maven2")
	resolver, err := adapter.NewUpstreamResolver("maven", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		panic(fmt.Sprintf("maven: building upstream resolver: %v", err))
	}
	a := &MavenAdapter{
		db:           db,
		cache:        cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		upstream:     strings.TrimRight(defaultURL, "/"),
		resolver:     resolver,
		// redirect-safe: per-index credentials must be stripped on cross-host/scheme redirect.
		httpClient:  adapter.NewRedirectSafeClient(5 * time.Minute),
		pomResolver: pomResolver,
	}
	a.router = a.buildRouter()
	return a
}

// DB exposes the adapter's database handle for tests.
func (a *MavenAdapter) DB() *config.GateDB { return a.db }

// idxURL returns the index URL, falling back to the default upstream for the
// default index (empty Name/URL).
func (a *MavenAdapter) idxURL(idx adapter.ResolvedIndex) string {
	if idx.URL != "" {
		return idx.URL
	}
	return a.upstream
}
```

> The `httpClient` switches from `NewProxyHTTPClient` to `NewRedirectSafeClient` (a superset — same timeout, adds cross-host/scheme auth-strip) because the download leg now forwards per-index credentials. Existing download tests must still pass (no cross-host redirect in them). `scanner.EcosystemMaven == "maven"` (`internal/scanner/interface.go`); the resolver is built with the literal `"maven"`.

- [ ] **Step 3: Update `main.go`**

In `cmd/shieldoo-gate/main.go`, keep the `mavenUpstream` string (the effective-POM resolver still needs a default base for its back-compat path) but: (a) make the resolver's HTTP client **redirect-safe**, and (b) pass the full `UpstreamSet` to the adapter. Change the resolver construction line and the adapter construction line:

```go
		pomResolver = effectivepom.NewResolver(mavenUpstream, adapter.NewRedirectSafeClient(5*time.Minute), pomResolverCfg)
		log.Info().Str("upstream", mavenUpstream).Msg("maven effective-POM resolver enabled")
	}
	mavenAdapter := maven.NewMavenAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.Maven, pomResolver)
```

(Only two lines change: `NewProxyHTTPClient` → `NewRedirectSafeClient` on the resolver, and `mavenUpstream` → `cfg.Upstreams.Maven` on the adapter. `mavenUpstream := cfg.Upstreams.Maven.DefaultOr("https://repo1.maven.org/maven2")` stays.)

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/adapter/maven/ -v && go build ./...
git add internal/adapter/maven/maven.go internal/adapter/maven/maven_test.go internal/adapter/maven/maven_typosquat_test.go cmd/shieldoo-gate/main.go
git commit -m "feat(maven): wire UpstreamResolver (default-only behaviour unchanged)"
```

Expected: all existing maven tests PASS (default path unchanged), build clean.

---

## Task 2: Maven — coordinate helpers (resolution key + metadata coordinate parse)

**Files:**
- Modify: `internal/adapter/maven/maven.go` (add helpers near `mavenArtifactID`)
- Test: `internal/adapter/maven/maven_test.go` (white-box — these test unexported helpers)

> These pure helpers feed resolution (Task 3) and download recovery (Task 4). They are unexported, so their tests live in the existing white-box `maven_test.go` (`package maven`).

- [ ] **Step 1: Write failing tests**

Add to `internal/adapter/maven/maven_test.go`:

```go
func TestParseMetadataCoord_ArtifactLevel(t *testing.T) {
	g, a, ok := parseMetadataCoord("com/mycompany/lib/maven-metadata.xml")
	require.True(t, ok)
	assert.Equal(t, "com.mycompany", g)
	assert.Equal(t, "lib", a)
}

func TestParseMetadataCoord_VersionLevelSnapshot(t *testing.T) {
	g, a, ok := parseMetadataCoord("com/mycompany/lib/1.0.0-SNAPSHOT/maven-metadata.xml")
	require.True(t, ok)
	assert.Equal(t, "com.mycompany", g)
	assert.Equal(t, "lib", a) // version segment dropped
}

func TestParseMetadataCoord_VersionLevelNumeric(t *testing.T) {
	g, a, ok := parseMetadataCoord("org/apache/commons/commons-lang3/3.14.0/maven-metadata.xml")
	require.True(t, ok)
	assert.Equal(t, "org.apache.commons", g)
	assert.Equal(t, "commons-lang3", a)
}

func TestParseMetadataCoord_TopLevel_NotOK(t *testing.T) {
	_, _, ok := parseMetadataCoord("maven-metadata.xml")
	assert.False(t, ok)
	_, _, ok = parseMetadataCoord("com/maven-metadata.xml") // only 1 segment → can't split g:a
	assert.False(t, ok)
}

func TestLooksLikeVersion(t *testing.T) {
	assert.True(t, looksLikeVersion("1.0.0"))
	assert.True(t, looksLikeVersion("1.0.0-SNAPSHOT"))
	assert.True(t, looksLikeVersion("2"))
	assert.False(t, looksLikeVersion("commons-lang3"))
	assert.False(t, looksLikeVersion("lib"))
	assert.False(t, looksLikeVersion(""))
}
```

Run: `go test ./internal/adapter/maven/ -run 'ParseMetadataCoord|LooksLikeVersion' -v` → FAIL (undefined helpers).

- [ ] **Step 2: Implement the helpers**

Add to `internal/adapter/maven/maven.go` (near `mavenArtifactID`, ~line 255):

```go
// coordName is the resolution/scoping key for a Maven artifact: the
// "groupId:artifactId" form. CanonicalPackageName is identity for Maven, so a
// `packages` glob like "com.mycompany:*" matches this verbatim.
func coordName(groupID, artifactID string) string {
	return groupID + ":" + artifactID
}

// parseMetadataCoord extracts (groupId, artifactId) from a maven-metadata.xml
// request path for upstream resolution. It handles both the artifact-level form
// (g/a/maven-metadata.xml) and the version-level form
// (g/a/{version}/maven-metadata.xml, used by SNAPSHOT resolution) by dropping a
// trailing segment that looks like a version. Returns ok=false for root-level or
// too-short paths (the caller then relays from the default index only). The
// version-level heuristic only affects which index a VERSION LISTING is fetched
// from — the artifact (.jar) download always resolves on the exact parsed
// coordinate, so a heuristic miss is never a scan bypass.
func parseMetadataCoord(cleanPath string) (groupID, artifactID string, ok bool) {
	base := strings.TrimSuffix(cleanPath, "maven-metadata.xml")
	base = strings.Trim(base, "/")
	if base == "" {
		return "", "", false
	}
	segs := strings.Split(base, "/")
	// Drop a trailing version segment (version-level / SNAPSHOT metadata).
	if len(segs) >= 3 && looksLikeVersion(segs[len(segs)-1]) {
		segs = segs[:len(segs)-1]
	}
	if len(segs) < 2 {
		return "", "", false // need at least group + artifact
	}
	artifactID = segs[len(segs)-1]
	groupID = strings.Join(segs[:len(segs)-1], ".")
	return groupID, artifactID, true
}

// looksLikeVersion reports whether a Maven path segment is most likely a version
// rather than an artifactId. Maven versions conventionally start with a digit or
// end with "-SNAPSHOT"; artifactIds conventionally do not start with a digit.
func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasSuffix(s, "-SNAPSHOT") {
		return true
	}
	return s[0] >= '0' && s[0] <= '9'
}

// firstIndexFor recovers the serving index for a download by re-resolving the
// coordinate (the artifact route carries groupId+artifactId). Returns the default
// index when resolution is empty (a scoped-miss download: the fetch then 404s on
// the absent upstream — correct, no public fallback).
func (a *MavenAdapter) firstIndexFor(coord string) adapter.ResolvedIndex {
	if idxs := a.resolver.ResolveForPackage(coord); len(idxs) > 0 {
		return idxs[0]
	}
	return adapter.ResolvedIndex{} // default
}
```

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/maven/ -run 'ParseMetadataCoord|LooksLikeVersion' -v && go build ./...
git add internal/adapter/maven/maven.go internal/adapter/maven/maven_test.go
git commit -m "feat(maven): coordinate-resolution + metadata-coordinate-parse helpers"
```

---

## Task 3: Maven — pass-through + metadata fan-out + scoped-miss audit

**Files:**
- Modify: `internal/adapter/maven/maven.go` (`handleRequest` dispatch, replace `proxyPassThrough` with a fan-out)
- Test: `internal/adapter/maven/maven_multi_index_test.go` (NEW, black-box `package maven_test`)

> **Scope:** every **per-coordinate** request fans out — `maven-metadata.xml` (parsed via `parseMetadataCoord`), `.pom`, checksums (`.sha1`/`.md5`/`.sha256`/`.asc`), and any unknown-extension pass-through (parsed via `parseMavenPath`, which yields groupId+artifactId). All are relayed **verbatim** (size-capped) — Maven metadata carries **no** download URLs, so there is nothing to rewrite. A claimed-namespace miss → 404 + namespaced `BLOCKED` audit. Root-level `maven-metadata.xml` (no parseable coordinate) relays from the **default** index only.
>
> **Test package:** the new multi-index tests go in a NEW file `internal/adapter/maven/maven_multi_index_test.go` declared `package maven_test` (black-box), so package-qualified helper/test code compiles unchanged alongside the existing white-box `maven_test.go`.

- [ ] **Step 1: Write failing tests**

Create `internal/adapter/maven/maven_multi_index_test.go`:

```go
package maven_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/maven"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func newMultiIndexMaven(t *testing.T, defaultURL string, extras []config.UpstreamIndex) *maven.MavenAdapter {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)
	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict: scanner.VerdictMalicious, QuarantineIfVerdict: scanner.VerdictSuspicious, MinimumConfidence: 0.7,
	}, nil)
	return maven.NewMavenAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: defaultURL, ExtraIndexes: extras}, nil)
}

func TestMavenAdapter_ExtraIndexPOM_FansOut(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/com/mycompany/lib/1.0.0/lib-1.0.0.pom" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<project><groupId>com.mycompany</groupId></project>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexMaven(t, "https://maven.invalid",
		[]config.UpstreamIndex{{Name: "corp", URL: corp.URL, Packages: []string{"com.mycompany:*"}}})
	req := httptest.NewRequest(http.MethodGet, "/com/mycompany/lib/1.0.0/lib-1.0.0.pom", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "com.mycompany")
}

func TestMavenAdapter_ExtraIndexMetadata_FansOut(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/com/mycompany/lib/maven-metadata.xml" {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<metadata><versioning><release>1.0.0</release></versioning></metadata>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexMaven(t, "https://maven.invalid",
		[]config.UpstreamIndex{{Name: "corp", URL: corp.URL, Packages: []string{"com.mycompany:*"}}})
	req := httptest.NewRequest(http.MethodGet, "/com/mycompany/lib/maven-metadata.xml", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "1.0.0")
}

func TestMavenAdapter_ScopedMissMetadata_Returns404(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexMaven(t, "https://maven.invalid",
		[]config.UpstreamIndex{{Name: "corp", URL: corp.URL, Packages: []string{"com.mycompany:*"}}})
	req := httptest.NewRequest(http.MethodGet, "/com/mycompany/ghost/maven-metadata.xml", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
```

Run: `go test ./internal/adapter/maven/ -run 'FansOut|ScopedMiss' -v` → FAIL (default-only pass-through ignores extra indexes).

- [ ] **Step 2: Rewire `handleRequest` dispatch + add the fan-out**

In `internal/adapter/maven/maven.go`, change the `maven-metadata.xml` branch and the pass-through branches of `handleRequest` to resolve a coordinate and fan out. Replace the body of `handleRequest` from the `maven-metadata.xml` check onward:

```go
	// maven-metadata.xml at any level — fan out per coordinate (verbatim relay,
	// no download URLs to rewrite). Root-level metadata with no parseable
	// coordinate relays from the default index only.
	if strings.HasSuffix(cleaned, "/maven-metadata.xml") || cleaned == "maven-metadata.xml" {
		if g, art, ok := parseMetadataCoord(cleaned); ok {
			a.serveFanOut(w, r, g, art, cleaned)
		} else {
			a.serveDefaultPassThrough(w, r, cleaned)
		}
		return
	}

	parsed, err := parseMavenPath(cleaned)
	if err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid path",
			Reason: err.Error(),
		})
		return
	}

	if parsed.scannable {
		idx := a.firstIndexFor(coordName(parsed.groupID, parsed.artifactID))
		a.downloadScanServe(w, r, idx, parsed, cleaned)
		return
	}

	// Pass-through (.pom, checksums, .asc, unknown) — fan out per coordinate.
	a.serveFanOut(w, r, parsed.groupID, parsed.artifactID, cleaned)
```

Replace the existing `proxyPassThrough` method with two methods — `serveDefaultPassThrough` (the old verbatim relay, default index only, used for root-level metadata) and the fan-out:

```go
// serveDefaultPassThrough forwards a request to the DEFAULT upstream verbatim
// (used for root-level maven-metadata.xml with no parseable coordinate). This is
// the pre-feature behaviour, byte-identical to today.
func (a *MavenAdapter) serveDefaultPassThrough(w http.ResponseWriter, r *http.Request, repoPath string) {
	target, err := url.JoinPath(a.upstream, repoPath)
	if err != nil {
		http.Error(w, "bad upstream path", http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// serveFanOut tries each resolved index for a per-coordinate metadata/POM/
// checksum request, serving the first that has it (200) verbatim. The default
// index relays all headers (status-identical to today); extra (low-trust) indexes
// relay a header allowlist only and are size-capped. A claimed-namespace miss →
// 404 + namespaced BLOCKED audit (no public fallback — dependency-confusion guard).
func (a *MavenAdapter) serveFanOut(w http.ResponseWriter, r *http.Request, groupID, artifactID, repoPath string) {
	coord := coordName(groupID, artifactID)
	for _, idx := range a.resolver.ResolveForPackage(coord) {
		served, err := a.tryServeMetadata(w, r, idx, repoPath)
		if err != nil {
			a.resolver.ObserveProbe(idx.Name, "error")
			continue
		}
		if served {
			a.resolver.ObserveProbe(idx.Name, "hit")
			return
		}
		a.resolver.ObserveProbe(idx.Name, "miss")
	}
	if claimants := a.resolver.ClaimingIndexNames(coord); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemMaven), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:%s:%s", eco, groupID, artifactID, adapter.TyposquatPlaceholderVersion),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index artifact not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	http.Error(w, "not found", http.StatusNotFound)
}

// tryServeMetadata fetches one index's metadata/POM/checksum at repoPath.
// (true,nil)=served; (false,nil)=404; (false,err)=transport/non-200/oversize. The
// body is relayed verbatim (size-capped — Maven metadata carries no download URLs).
func (a *MavenAdapter) tryServeMetadata(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, repoPath string) (bool, error) {
	target, err := url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), repoPath)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}
	if h := a.resolver.AuthHeader(idx); h != "" {
		req.Header.Set("Authorization", h)
	}
	resp, err := a.resolver.Client().Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("maven: index %q returned %d", idx.Name, resp.StatusCode)
	}
	// Cap the metadata body from a low-trust extra index (POMs/metadata/checksums
	// are small). Read fully so the size guard runs before bytes reach the client;
	// fail closed on exceed.
	const maxMetadataSize = 16 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("maven: index %q metadata exceeds size limit", idx.Name)
	}
	if idx.Name == "" {
		for key, vals := range resp.Header {
			if strings.EqualFold(key, "Content-Length") {
				continue
			}
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
	} else {
		for _, h := range []string{"Content-Type", "ETag", "Last-Modified"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
	return true, nil
}
```

Add `"encoding/json"` to the `maven.go` import block (the scoped-miss audit marshals the claimants).

> Delete the now-unused old `proxyPassThrough` method body (replaced by `serveDefaultPassThrough` + the fan-out). The final catch-all fallback line in `handleRequest` (`a.proxyPassThrough(w, r, cleaned)` for "anything else") is removed — every path now resolves to scannable or pass-through above.

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/maven/ -v && go build ./...
git add internal/adapter/maven/maven.go internal/adapter/maven/maven_multi_index_test.go
git commit -m "feat(maven): per-coordinate metadata/POM fan-out + scoped-miss audit"
```

Expected: the new fan-out tests PASS; existing default-path tests PASS (the default index relays all headers as before).

---

## Task 4: effective-POM resolver — walk the parent chain against the serving index

**Files:**
- Modify: `internal/maven/effectivepom/resolver.go` (`Resolve` → wrapper; new `ResolveFrom`; `pomURL`/`fetchAndParse` take baseURL+auth; per-index cache key)
- Modify: `internal/maven/effectivepom/cache.go` (cache keyed by an explicit string)
- Test: `internal/maven/effectivepom/resolver_test.go`

> **Ordering:** this task is **pure-additive** — it adds `ResolveFrom` and keeps `Resolve(ctx, c)` as a back-compat wrapper, so every existing caller (tests, and `main.go`'s nothing-yet) stays green and the package compiles standalone. It lands **before** the download-leg change (Task 5) that consumes `ResolveFrom`, so each task builds at its own commit.
>
> **Why:** the resolver enriches a scanned artifact with parent-chain licenses. Today it fetches POMs from a single hardcoded `upstreamURL`, so a **private** artifact's parents are fetched from **public** Maven Central (wrong index, no auth → 404 → fewer licenses; and a private parent GAV could leak to public). It must walk against the **serving index** (URL + auth) that the adapter resolved for the artifact. Decision: pin the *entire* walk to the serving index (best-effort, fail-open; never re-resolve per parent — that would add a dependency-confusion surface). The per-(baseURL,GAV) cache key prevents cross-index license bleed.

- [ ] **Step 1: Make the cache key explicit (cache.go)**

In `internal/maven/effectivepom/cache.go`, change `get`/`put` to take an explicit key string instead of computing `coords.String()` internally:

```go
// get returns the cached POM result for the given key, or nil if not found or expired.
func (c *pomCache) get(key string) *pomResult {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.insertedAt) > c.ttl {
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}
	return entry.result
}

// put stores a POM result under the given key. Evicts the oldest entry at capacity.
func (c *pomCache) put(key string, result *pomResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		c.entries[key] = &cachedPOM{result: result, insertedAt: time.Now()}
		return
	}
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range c.entries {
			if first || v.insertedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.insertedAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}
	c.entries[key] = &cachedPOM{result: result, insertedAt: time.Now()}
}
```

The existing `pomCache.get(coords)`/`put(coords, …)` calls are in **`resolver_test.go`** (there is **no** `cache_test.go`). Find them — `grep -n '\.get(\|\.put(\|newPOMCache' internal/maven/effectivepom/resolver_test.go` — and update each to pass a string key, e.g. `c.put(coords.String(), result)` / `c.get(coords.String())`.

- [ ] **Step 2: Add `ResolveFrom` + back-compat wrapper (resolver.go)**

In `internal/maven/effectivepom/resolver.go`, keep the `Resolver` struct and `NewResolver` unchanged (the `upstreamURL` field stays as the default base for the back-compat `Resolve`). Replace `Resolve` and the private `fetchAndParse`/`pomURL` so the base URL and auth header flow through the whole walk and into the cache key:

```go
// Resolve walks the parent POM chain for the coordinates against the resolver's
// DEFAULT upstream (back-compat — used by tests and any caller that has no
// resolved index). New callers should use ResolveFrom.
func (r *Resolver) Resolve(ctx context.Context, c Coords) []string {
	return r.ResolveFrom(ctx, c, r.upstreamURL, "")
}

// ResolveFrom walks the parent POM chain for the coordinates against a SPECIFIC
// base URL (the serving upstream index the artifact was fetched from) with an
// optional Authorization header (the index's per-index credential). The entire
// walk is pinned to baseURL — parents are NOT re-resolved across indexes (best-
// effort license enrichment, fail-open; pinning avoids a dependency-confusion
// surface). The per-(baseURL,GAV) cache key prevents cross-index license bleed.
//
// Returns nil (not an error) on network failure, depth/cycle limits, or no
// licenses found. Errors are logged, never propagated — the resolver is
// best-effort enrichment, not a gate.
func (r *Resolver) ResolveFrom(ctx context.Context, c Coords, baseURL, authHeader string) []string {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		baseURL = r.upstreamURL
	}
	ctx, cancel := context.WithTimeout(ctx, r.resolverTimeout)
	defer cancel()

	seen := make(map[string]bool, r.maxDepth)
	current := c
	for depth := 0; depth < r.maxDepth; depth++ {
		key := current.String()
		if seen[key] {
			log.Warn().Str("coords", key).Msg("effectivepom: cycle detected in parent chain")
			return nil
		}
		seen[key] = true

		cacheKey := baseURL + "|" + key
		if cached := r.cache.get(cacheKey); cached != nil {
			if len(cached.Licenses) > 0 {
				return cached.Licenses
			}
			if cached.Parent != nil {
				current = *cached.Parent
				continue
			}
			return nil
		}

		result, err := r.fetchAndParse(ctx, current, baseURL, authHeader)
		if err != nil {
			log.Warn().Err(err).Str("coords", key).Msg("effectivepom: fetch/parse failed, failing open")
			return nil
		}
		r.cache.put(cacheKey, result)

		if len(result.Licenses) > 0 {
			return result.Licenses
		}
		if result.Parent != nil {
			current = *result.Parent
			continue
		}
		return nil
	}

	log.Warn().Str("coords", c.String()).Int("max_depth", r.maxDepth).Msg("effectivepom: max depth exceeded")
	return nil
}

// fetchAndParse downloads a standalone .pom from baseURL (with optional auth) and parses it.
func (r *Resolver) fetchAndParse(ctx context.Context, c Coords, baseURL, authHeader string) (*pomResult, error) {
	pomURL := r.pomURL(baseURL, c)

	fetchCtx, cancel := context.WithTimeout(ctx, r.fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, pomURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", pomURL, err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", pomURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", pomURL, resp.StatusCode)
	}

	// Defence in depth (the client is also redirect-safe): reject a cross-host
	// redirect so a private POM fetch's credential cannot be exfiltrated.
	if resp.Request != nil && resp.Request.URL != nil {
		origHost := mustParseHost(pomURL)
		finalHost := resp.Request.URL.Host
		if origHost != "" && finalHost != "" && origHost != finalHost {
			return nil, fmt.Errorf("effectivepom: cross-host redirect detected (%s → %s), rejecting", origHost, finalHost)
		}
	}

	return parsePOM(resp.Body)
}

// pomURL constructs the standalone .pom URL against baseURL:
// {baseURL}/{groupPath}/{artifactId}/{version}/{artifactId}-{version}.pom
func (r *Resolver) pomURL(baseURL string, c Coords) string {
	groupPath := strings.ReplaceAll(c.GroupID, ".", "/")
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		baseURL, groupPath, c.ArtifactID, c.Version, c.ArtifactID, c.Version)
}
```

- [ ] **Step 3: Add a test for index pinning + auth + cache isolation**

Add to `internal/maven/effectivepom/resolver_test.go`:

```go
func TestResolveFrom_PinsToBaseURLAndSendsAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<project><licenses><license><name>Apache-2.0</name></license></licenses></project>`))
	}))
	defer srv.Close()
	resolver := NewResolver("https://default.invalid", srv.Client(), Config{MaxDepth: 5})
	licenses := resolver.ResolveFrom(context.Background(), Coords{
		GroupID: "com.mycompany", ArtifactID: "lib", Version: "1.0.0",
	}, srv.URL, "Bearer tok-xyz")
	require.Equal(t, []string{"Apache-2.0"}, licenses)
	assert.Equal(t, "Bearer tok-xyz", gotAuth)
}

func TestResolveFrom_CacheIsolatedByBaseURL(t *testing.T) {
	// Two servers return different licenses for the SAME GAV. The per-(baseURL,GAV)
	// cache key must keep them distinct (no cross-index bleed).
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<project><licenses><license><name>Apache-2.0</name></license></licenses></project>`))
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<project><licenses><license><name>MIT</name></license></licenses></project>`))
	}))
	defer srvB.Close()
	resolver := NewResolver("https://default.invalid", srvA.Client(), Config{MaxDepth: 5})
	c := Coords{GroupID: "com.mycompany", ArtifactID: "lib", Version: "1.0.0"}
	a := resolver.ResolveFrom(context.Background(), c, srvA.URL, "")
	b := resolver.ResolveFrom(context.Background(), c, srvB.URL, "")
	assert.Equal(t, []string{"Apache-2.0"}, a)
	assert.Equal(t, []string{"MIT"}, b) // NOT the cached Apache-2.0 from srvA
}
```

(Ensure `net/http/httptest` is imported in the test file — it already is, given the existing `httptest.NewServer` usages.)

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/maven/effectivepom/ -v && go build ./...
git add internal/maven/effectivepom/resolver.go internal/maven/effectivepom/cache.go internal/maven/effectivepom/resolver_test.go
git commit -m "feat(maven): effective-POM resolver walks parent chain against serving index (URL + auth)"
```

Expected: all effectivepom tests PASS (existing `Resolve` wrapper preserved + the two new `ResolveFrom` tests), build clean. The adapter still calls the old `Resolve` (unchanged until Task 5), so `./...` builds.

---

## Task 5: Maven — download index recovery + namespaced artifact IDs + auth (RELEASE GATE)

**Files:**
- Modify: `internal/adapter/maven/maven.go` (`downloadScanServe` signature + body; thread the serving index into the effective-POM call; add `downloadToTempAuthed`)
- Test: `internal/adapter/maven/maven_multi_index_test.go`

> The scannable download is the **scan chokepoint** and the non-negotiable release gate. `handleRequest` (Task 3) now calls `a.downloadScanServe(w, r, idx, parsed, cleaned)` with the resolved index. `ResolveFrom` already exists (Task 4), so this task compiles at its own commit.

- [ ] **Step 1: Write the failing tests**

Add to `internal/adapter/maven/maven_multi_index_test.go` (and add `adapter` to its imports: `"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"`):

```go
func TestMavenAdapter_ExtraIndexJarDownload_ScansAndNamespaces(t *testing.T) {
	var sentAuth string
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/com/mycompany/lib/1.0.0/lib-1.0.0.jar" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PK\x03\x04dummy-jar-bytes"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_MVN_CORP_TOK", "tok-xyz")
	a := newMultiIndexMaven(t, "https://maven.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"com.mycompany:*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_MVN_CORP_TOK"},
	}})
	req := httptest.NewRequest(http.MethodGet, "/com/mycompany/lib/1.0.0/lib-1.0.0.jar", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code) // no scanners → clean → served
	assert.Equal(t, "Bearer tok-xyz", sentAuth)
	status, err := adapter.GetArtifactStatus(a.DB(), "maven__corp:com.mycompany:lib:1.0.0")
	require.NoError(t, err)
	require.NotNil(t, status)
}

// A malicious cross-host download redirect must NOT carry the per-index
// credential to the redirect target (NewRedirectSafeClient strips it).
func TestMavenAdapter_DownloadRedirectToForeignHost_StripsAuth(t *testing.T) {
	var foreignAuth string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PK\x03\x04dummy-jar-bytes"))
	}))
	t.Cleanup(foreign.Close)
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+r.URL.Path, http.StatusFound) // 302 to a different host
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_MVN_CORP_TOK", "tok-secret")
	a := newMultiIndexMaven(t, "https://maven.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"com.mycompany:*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_MVN_CORP_TOK"},
	}})
	req := httptest.NewRequest(http.MethodGet, "/com/mycompany/lib/1.0.0/lib-1.0.0.jar", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Empty(t, foreignAuth, "Authorization must be stripped on cross-host redirect")
}
```

Run: `go test ./internal/adapter/maven/ -run 'JarDownload_ScansAndNamespaces|RedirectToForeignHost' -v` → FAIL (artifact row under bare `maven:` not `maven__corp:`; no auth threading).

- [ ] **Step 2: Namespace + recover index + thread auth in `downloadScanServe`**

In `internal/adapter/maven/maven.go`, change `downloadScanServe`'s signature to take the resolved index and namespace the artifact ID. Replace the signature and the first lines:

```go
// downloadScanServe implements the full download -> scan -> policy -> serve pipeline.
func (a *MavenAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, parsed *parsedPath, repoPath string) {
	ctx := r.Context()

	// Namespace the artifact ID by the serving index (eco__<index>); the default
	// index keeps the bare eco. The scanner Ecosystem carries the SAME namespaced
	// segment so the persisted artifact row + cache isolate per index (the release
	// gate: a private artifact is queryable under maven__<index>).
	eco := adapter.NamespacedEcosystem(string(scanner.EcosystemMaven), idx.Name)
	artifactID := fmt.Sprintf("%s:%s:%s:%s", eco, parsed.groupID, parsed.artifactID, parsed.version)
	coordNm := parsed.groupID + ":" + parsed.artifactID
```

Then, **replacing the existing `artifactID := mavenArtifactID(...)` and `coordName := parsed.groupID + ":" + parsed.artifactID` lines** (the typosquat pre-scan call already uses the local `coordName` variable — rename its usage to `coordNm`):

- update the typosquat call to use the renamed local: `if a.handleTyposquatPreScan(w, r, coordNm, parsed.version) {` (the local download-coordinate variable is renamed `coordName` → `coordNm` to avoid shadowing the new **package-level** `coordName(groupID, artifactID)` helper from Task 2 — `go vet` flags the shadow otherwise)
- In the cached-serve branch's async re-scan (the `adapter.TriggerAsyncScan(...)` near line 423), change `Ecosystem: scanner.EcosystemMaven` → `Ecosystem: scanner.Ecosystem(eco)`.
- Change the download URL construction (line ~471) from `url.JoinPath(a.upstream, repoPath)` to:
  ```go
	upstreamURL, err := url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), repoPath)
  ```
- Change the download call (line ~477) from `downloadToTemp(pctx, upstreamURL, a.httpClient)` to:
  ```go
	tmpPath, size, sha, err := downloadToTempAuthed(pctx, upstreamURL, a.resolver.AuthHeader(idx), a.httpClient)
  ```
- In the `scanner.Artifact` built at step 4 (line ~497), change `Ecosystem: scanner.EcosystemMaven` → `Ecosystem: scanner.Ecosystem(eco)`.
- Thread the serving index into the effective-POM call (step 4b, line ~512-518): change `a.pomResolver.Resolve(pctx, coords)` to:
  ```go
		if rawLicenses := a.pomResolver.ResolveFrom(pctx, coords, strings.TrimRight(a.idxURL(idx), "/"), a.resolver.AuthHeader(idx)); len(rawLicenses) > 0 {
  ```
  (`ResolveFrom` was added in Task 4, so this line compiles. It pins the effective-POM parent-chain walk to the serving index's base URL + per-index auth.)

> **Note on `mavenArtifactID`:** it is no longer called by `downloadScanServe`. Grep for other callers (`grep -n mavenArtifactID internal/adapter/maven/`); if none remain outside tests, leave it (a test may use it) or delete it if unused. Do not break `maven_test.go`.

Add `downloadToTempAuthed` (copy of the gomod helper, maven-flavoured temp prefix) and keep the existing `downloadToTemp` only if another caller remains:

```go
// downloadToTempAuthed downloads url into a temporary file, returning (path,
// size, sha256hex, error). When authHeader is non-empty it is sent as the
// Authorization header (per-index private-repo credential); the client must be
// redirect-safe so the header is stripped on a cross-host/scheme redirect.
func downloadToTempAuthed(ctx context.Context, rawURL, authHeader string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("maven: download: building request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("maven: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("maven: download: upstream returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "shieldoo-gate-maven-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("maven: download: creating temp file: %w", err)
	}
	defer tmp.Close()

	h := sha256.New()
	mw := io.MultiWriter(tmp, h)

	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("maven: download: writing temp file: %w", err)
	}

	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}
```

> If `downloadToTemp` is now unused (grep `grep -n 'downloadToTemp(' internal/adapter/maven/`), delete it to avoid a dead-code lint failure. Keep it only if a test still calls it.

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/maven/ -v && go build ./...
git add internal/adapter/maven/maven.go internal/adapter/maven/maven_multi_index_test.go
git commit -m "feat(maven): download index recovery (re-resolve) + namespaced artifact IDs + per-index auth"
```

Expected: the release-gate tests PASS (artifact row under `maven__corp:…`; cross-host redirect strips auth); all existing maven tests PASS; build clean (`ResolveFrom` from Task 4 resolves the effective-POM call).

---

## Task 6: Maven — config.example.yaml + example project

**Files:**
- Modify: `config.example.yaml`
- Create: `examples/maven-private-repo/README.md`, `examples/maven-private-repo/settings.xml.example`
- Modify: `examples/README.md`

- [ ] **Step 1:** Add a `maven` multi-index block to `config.example.yaml` mirroring the npm/gomod ones (default + a scoped private repo with env-var `auth`; note `files_host` is **PyPI-only** and rejected for maven). Place it near the existing `maven:` upstream key:

```yaml
  maven:
    default: "https://repo1.maven.org/maven2"
    # extra_indexes:
    #   - name: "corp"
    #     url: "https://nexus.internal.example.com/repository/maven-releases"
    #     packages: ["com.mycompany:*", "com.acme:*"]   # REQUIRED: extra indexes must be scoped
    #     auth:
    #       type: "bearer"                # "bearer" | "basic"
    #       token_env: "SGW_MAVEN_CORP_TOKEN"
```

- [ ] **Step 2:** `examples/maven-private-repo/README.md` documenting: configure `upstreams.maven.extra_indexes` with a scoped private repo (env-var auth), point Maven's `settings.xml` `<mirror>` at the gate so **all** repository traffic flows through it, `mvn dependency:get` the private artifact **through** the gate (scanned + cached under `maven__<index>`, not bypassed). Note the effective-POM resolver fetches parent POMs from the same private index. `settings.xml.example`:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>shieldoo-gate</id>
      <name>Shieldoo Gate</name>
      <url>http://localhost:8085</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

Reference `tests/e2e-shell/test_maven_multi_index.sh` as the executable spec. Add a line to `examples/README.md`.

- [ ] **Step 3:** Verify + commit:

```bash
make build && make lint && make test
git add config.example.yaml examples/maven-private-repo/ examples/README.md
git commit -m "docs(maven): document multi-index config + private-repo example"
```

---

## Task 7: Config migration — maven repo configs → `default:` form (Phase 4b parity)

**Files:** `docker/config.yaml`, `examples/deploy/config.yaml`, `.deploy/config.yaml` (skip if gitignored/absent — CI-safe, per Phase 4b precedent), Helm `values.yaml` + `configmap.yaml`.

> Shape-only, **no behaviour change**, **no production `extra_indexes`**. Mirror exactly how Phases 4b/5/6 migrated `pypi`/`npm`/`nuget`/`rubygems`/`gomod`.

- [ ] **Step 1:** In each committed config that has a bare-string `maven:`, change `maven: "https://repo1.maven.org/maven2"` → 
  ```yaml
  maven:
    default: "https://repo1.maven.org/maven2"
  ```
  First locate them: `grep -rn 'maven:' docker/config.yaml examples/deploy/config.yaml .deploy/config.yaml deploy/helm 2>/dev/null` (the Helm chart keys may differ — match the existing pypi/npm structure in `values.yaml` + `configmap.yaml`). Leave any `maven_resolver:` block untouched.
- [ ] **Step 2:** Run the Phase 4b config-validation regression test (find it: `grep -rn 'TestAllCommittedConfigs\|loadAndValidate\|committed' internal/config/`) — it must still pass: `go test ./internal/config/ -run 'Committed|Config' -v`.
- [ ] **Step 3:** Commit: 
  ```bash
  git add docker/config.yaml examples/deploy/config.yaml deploy/helm 2>/dev/null
  git commit -m "config(maven): restructure committed upstreams to default: form (multi-index ready)"
  ```

---

## Task 8: E2E harness — private Maven artifact + multi-index scenarios

**Files:**
- Create: `tests/e2e-shell/fixtures/private-index/gen-maven.sh` + committed `www/maven/` subtree.
- Modify: `tests/e2e-shell/fixtures/private-index/Caddyfile` (serve the maven tree if not already covered by the existing static file_server).
- Modify: `tests/e2e-shell/config.e2e.yaml` (maven multi-index).
- Create: `tests/e2e-shell/test_maven_multi_index.sh`.
- Modify: `tests/e2e-shell/run.sh` + `run_all.sh` (register it).

> **Harness reuse:** the shared `private-index` Caddy already serves PyPI/npm/NuGet/RubyGems/GOPROXY trees at `https://private-index:8443` over the test CA. Serve the Maven tree under a `/maven` base path (so the index `url` is `https://private-index:8443/maven`), avoiding any collision with the other ecosystems' trees. Reuse the CA so the https-only invariant is preserved.

- [ ] **Step 1: Maven fixture** — `gen-maven.sh` writes a tiny artifact tree under `tests/e2e-shell/fixtures/private-index/www/maven/`:
  - `com/mycompany/lib/1.0.0/lib-1.0.0.pom` — a minimal valid POM:
    ```xml
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <modelVersion>4.0.0</modelVersion>
      <groupId>com.mycompany</groupId>
      <artifactId>lib</artifactId>
      <version>1.0.0</version>
      <licenses><license><name>Apache-2.0</name></license></licenses>
    </project>
    ```
  - `com/mycompany/lib/1.0.0/lib-1.0.0.jar` — a tiny valid jar (a zip; e.g. `printf 'PK\x03\x04' > … ` is enough for the gate's scan-pipeline test, but prefer `(cd "$tmp" && echo x > a.txt && zip -q lib-1.0.0.jar a.txt)` so it is a real zip — Trivy is not registered in this E2E so content is not deeply inspected).
  - `com/mycompany/lib/1.0.0/lib-1.0.0.jar.sha1` — the SHA-1 of the jar (so a real `mvn` checksum verify passes if it is exercised): `sha1sum lib-1.0.0.jar | cut -d' ' -f1 > lib-1.0.0.jar.sha1`.
  - `com/mycompany/lib/maven-metadata.xml` — artifact-level metadata listing 1.0.0:
    ```xml
    <metadata><groupId>com.mycompany</groupId><artifactId>lib</artifactId><versioning><latest>1.0.0</latest><release>1.0.0</release><versions><version>1.0.0</version></versions></versioning></metadata>
    ```
  Commit the tree.

- [ ] **Step 2: Caddyfile + config.e2e.yaml** — verify the existing `private-index` Caddy `file_server` serves `/maven/...` static files with sane content types (`.pom`/`.xml` as XML, `.jar` as octet-stream); add a `handle_path /maven/*` or rely on the existing root `file_server browse` if it already maps `www/`. Wire `config.e2e.yaml` (replace the bare `maven: "https://repo1.maven.org/maven2"` at line ~50 with the structured form):

```yaml
  maven:
    default: "https://repo1.maven.org/maven2"
    extra_indexes:
      - name: "private"
        url: "https://private-index:8443/maven"
        packages: ["com.mycompany:*"]
```

- [ ] **Step 3: test script** — `tests/e2e-shell/test_maven_multi_index.sh` defines `test_maven_multi_index()` (sourced; no `set -e`; uses `helpers.sh`, mirrors `test_gomod_multi_index.sh`). Scenarios:
  - **MV1 back-compat:** `GET "$E2E_MAVEN_URL/org/apache/commons/commons-lang3/maven-metadata.xml"` → 200 via the default upstream (real Maven Central). (Skip with `log_skip` if outbound network to Central is unavailable in the runner — match how other tests gate on `$E2E_ALLOW_NETWORK` if present.)
  - **MV2 release gate:** two parts.
    - `curl "$E2E_MAVEN_URL/com/mycompany/lib/1.0.0/lib-1.0.0.pom"` → 200 (fan-out hit from the private index; body contains `com.mycompany`);
    - `curl "$E2E_MAVEN_URL/com/mycompany/lib/1.0.0/lib-1.0.0.jar"` through the gate → HTTP 200; then assert an artifact row under ecosystem `maven__private` via `api_jq "/api/v1/artifacts?ecosystem=maven__private"` (mirror the gomod `go__private` assertion). **This is the hard release gate** — if the artifact row is absent, a private artifact was served without scanning and the phase is NOT done.
  - **MV3 scoped-miss:** `GET "$E2E_MAVEN_URL/com/mycompany/ghost/maven-metadata.xml"` → 404; assert a `BLOCKED` audit under `maven__private:com.mycompany:ghost` (mirror the gomod M3 audit assertion).

- [ ] **Step 4: register** in `run.sh` + `run_all.sh` (source `test_maven_multi_index.sh`; call `test_maven_multi_index` after `test_maven`).

- [ ] **Step 5: run** (logfile convention):

```bash
docker compose -f tests/e2e-shell/docker-compose.e2e.yml build > /tmp/e2e-p7-build.log 2>&1 && \
  SGW_POLICY_MODE=strict docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
  --abort-on-container-exit --exit-code-from test-runner > /tmp/e2e-p7.log 2>&1; \
  echo "EXIT=$?"; \
  docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v --remove-orphans >> /tmp/e2e-p7.log 2>&1; \
  grep -E "Multi-Index|RELEASE GATE|MV[0-9]:|Passed:|Failed:" /tmp/e2e-p7.log
```

Expected: MV1–MV3 PASS alongside every prior PyPI/npm/NuGet/RubyGems/gomod multi-index gate + all back-compat suites. **The `maven__private` artifact-row assertion is the hard release gate.**

- [ ] **Step 6: commit**

```bash
git add tests/e2e-shell/
git commit -m "test(e2e): maven multi-index scenarios (scanned+cached, scoped-miss)"
```

---

## Task 9: Docs + implementation security review

**Files:**
- Modify: `docs/adapters.md` (Maven "Multi-Upstream Indexes" section)
- Modify: `docs/development/e2e-testing.md` (scenario matrix + inventory)

- [ ] **Step 1:** Add a "Multi-Upstream Indexes" section to the Maven adapter docs in `docs/adapters.md`. Cover: resolution order (default first, then unscoped extras; claimed names resolve only to claiming indexes), scoping on `groupId:artifactId` globs, `eco__<index>` namespacing, download index recovery via re-resolution, the **verbatim metadata relay** (Maven embeds no download URLs — nothing to rewrite), the effective-POM resolver pinning the parent walk to the serving index, and the **limitations**:
  - **Extra indexes MUST be `packages`-scoped** (mirrors gomod/npm/nuget): the flat-coordinate download leg recovers the serving index by re-resolving the coordinate, so an *unscoped* extra index cannot be recovered on download → its artifact would be re-fetched from the default. Unscoped extra indexes are unsupported for Maven.
  - **`maven-metadata.xml` version-level (SNAPSHOT) coordinate parse is heuristic** (`looksLikeVersion`): mis-detection only mis-resolves a *version listing*, never bypasses a scan (the `.jar` download always resolves on the exact parsed coordinate). Edge case to document explicitly: an artifactId that **starts with a digit** (e.g. `3d-core`, `4suite`) on a version-level metadata path is mis-classified as a version and dropped — again only affecting a version listing, never a scan.
  - **Effective-POM parent chain is pinned to the serving index** and is best-effort/fail-open: a parent absent from a private index simply yields fewer enriched licenses; it never blocks serving.
- [ ] **Step 2:** Extend `docs/development/e2e-testing.md` §5.4 scenario matrix with the Maven (MV1–MV3) rows, and §4 inventory with `maven_multi_index`.
- [ ] **Step 3:** Run the **security-code-review** skill on the maven + effectivepom diff (mandate (d)): confirm (a) the download leg re-resolves to the correct scoped index + namespaces (no public fallback for a claimed name); (b) no metadata-rewrite surface mis-handled (verbatim relay, size-capped, header allowlist for extra indexes); (c) no token leak on redirect on **either** the metadata fan-out, the artifact download, or the effective-POM POM fetch (redirect-safe client everywhere + cross-host rejection in the resolver); (d) scoped-miss never falls through to public + is audited; (e) the effective-POM walk cannot be coerced into fetching an artifact (`.jar`) or leaking a private parent GAV to public.
- [ ] **Step 4:** Commit docs: `docs(maven): document multi-upstream-index behaviour + limitations`.

---

## Inherited deferred findings (shared cross-adapter follow-ups — NOT new regressions)

The plan security review confirmed Maven **inherits** the two MEDIUM findings already deferred for npm/nuget/rubygems/gomod (Phase 6 plan, "Two MEDIUM findings deferred"). They are not new and not Phase-7 blockers, but Maven must be **named** in the cross-adapter follow-up so it is not silently dropped:

1. **Breaker-open claimed-name download fallback.** `firstIndexFor` (Task 2) returns the default index when `ResolveForPackage` is empty. For a *claimed* coordinate whose every claiming index is breaker-open, the download leg would fetch from the default (public) — still **scanned** (no bypass), but a private coordinate could be satisfied by a public package during a private-index outage. Same posture as gomod's copied `firstIndexFor`. The metadata leg is **not** affected (it 404s via `ClaimingIndexNames`). Follow-up: have the download leg consult `ClaimingIndexNames` and refuse (404) instead of defaulting, across **all five** flat-/namespaced adapters incl. Maven.
2. **Unscoped extra index is WARNed, not rejected.** A Maven extra index without `packages` cannot be recovered on the download leg (re-resolution returns the default) → content substitution. Documented as unsupported (decision table + Task 9). Follow-up: make an unscoped extra index a fatal config error (affects npm/nuget/rubygems/gomod/maven equally).

## Phase 7 done-when

- [ ] Maven default-only config behaves identically to pre-feature on the served (200) path (verbatim relay of metadata/POM/checksums; unchanged scan→serve for artifacts) — all legacy maven + `test_license_maven` tests green. The only deliberate changes: a per-coordinate 404/5xx now returns a small `"not found"` (status-identical) body.
- [ ] Per-coordinate metadata/POM/checksum requests resolve across indexes (ordered fallback + `groupId:artifactId` glob scoping); first hit serves verbatim; no rewrite (Maven has no metadata download-URL surface).
- [ ] The artifact download leg recovers the serving index by re-resolution, carries per-index env-var auth (redirect-safe), and stores artifacts under `maven__<index>` (scanner `Ecosystem` namespaced so the artifact row + cache isolate).
- [ ] The effective-POM resolver walks the parent chain against the **serving index** (URL + auth), cache keyed per-(baseURL,GAV); credentials are redirect-safe; it remains best-effort/fail-open.
- [ ] Scoped-namespace miss → 404 (no public fallback) + namespaced `BLOCKED` audit + `upstream_scoped_miss_total` metric.
- [ ] Committed configs migrated to `default:` form (no prod `extra_indexes`); config-validation regression green.
- [ ] `make build && make lint && make test` green.
- [ ] Extra indexes are `packages`-scoped (unscoped unsupported — documented).
- [ ] **E2E green, including the new `maven__private` scan+cache release-gate assertion, the scoped-miss 404+audit, and the cross-host-redirect auth-strip unit test.**
- [ ] Example added; docs updated; implementation security review APPROVED.
