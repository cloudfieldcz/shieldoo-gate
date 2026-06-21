# Multi-Upstream Indexes — Phase 6: RubyGems + Go modules

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run E2E redirected to a log file, then tail it (per the repo's E2E-via-logfile convention).

**Goal:** Extend the proven Phase 2 resolver + Phase 3/5 reference pattern to the **RubyGems** and **Go modules** adapters: fan per-package metadata across the default + extra indexes (ordered fallback + glob scoping), recover the serving index on the download leg by **re-resolving the package/module name**, namespace artifact IDs via `eco__<index>`, carry per-index env-var auth (redirect-safe), and audit scoped-misses. Extend the Phase 4/5 docker-compose E2E harness with a private gem + a private Go module and prove the non-negotiable release gate: **a secondary-index artifact is scanned + cached, not bypassed.**

**Architecture (key simplification vs Phase 5):** Neither RubyGems nor Go modules embeds artifact download URLs in metadata the way npm (`dist.tarball`) and NuGet (`packageContent`) do — **the client constructs the download URL itself from the source/GOPROXY base.** The scan chokepoint is therefore the **unconditional download route** (`/gems/{file}`, `…/@v/{ver}.zip`), which already scans every artifact regardless of index. So Phase 6 has **almost no metadata-rewrite surface**:

- **Go modules:** zero rewrite. `.info`/`.mod`/`@v/list`/`@latest` carry no download URLs → relayed verbatim. The only multi-index work is resolver wiring, per-module metadata **fan-out** (to discover private modules + 404 scoped-misses), and download index recovery + namespacing + auth on the `.zip` leg.
- **RubyGems:** the one download-URL field is `gem_uri` in `/api/v1/gems/{name}.json`. For **extra** indexes this is rewritten **fail-closed** (host must be the index/files host) — mirroring npm — so the uniform "no foreign download host" mandate holds. `/api/v1/versions/{name}.json` (no download URL) is relayed. The legacy `/quick/Marshal.4.8/*` gemspec + the whole-index `/specs*.4.8.gz` stay **default-only** (index-wide / not safely rewritable — a documented limitation, mirroring NuGet's service-index + npm's per-version-manifest default-only).

**Tech Stack:** Go 1.25, `github.com/go-chi/chi/v5`, `encoding/json` (RubyGems `gem_uri` rewrite), the Phase 2 `adapter.UpstreamResolver`, `net/http/httptest` (unit/integration), docker-compose + Caddy + the real `gem`/`go` clients (E2E).

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

---

## Security mandate (carried from the plan index — non-negotiable for this phase)

Every per-ecosystem metadata path is a potential scan-bypass surface. RubyGems + Go modules MUST:

- **(a)** route every artifact **download** through the gate's scanning download route (it already does — the client constructs `/gems/{file}` and `…/@v/{ver}.zip` against the gate); the download leg MUST recover the **correct** serving index by re-resolution so a scoped private artifact is fetched from its private index and stored under `eco__<index>` (never silently fetched from public);
- **(b)** for RubyGems extra-index `/api/v1/gems/{name}.json`, **fail closed (502)** if the `gem_uri` host is not the index/files host, or the body is not valid JSON — never relay a metadata doc that points a client at an unscanned host;
- **(c)** a **claimed-namespace miss** returns 404 (no public fallback) and is audited under `eco__<firstClaimant>` — the dependency-confusion guard (Phase 2 `ResolveForPackage` already returns only claiming indexes for a claimed name);
- **(d)** get a dedicated **security review of the implementation** (security-code-review skill), not just this plan.

Default-index behaviour stays **status-identical** to today on the served (200) path (RubyGems `handlePassThrough` verbatim relay; Go modules `proxyPassThrough` verbatim stream). One deliberate change: a per-package **404** from the default index now flows through the fan-out's scoped-miss tail and returns a small JSON/`"not found"` body instead of relaying the upstream's 404 body — `gem`/`bundler`/`go` clients key only on the status code, so this is safe (recorded by the dev review).

---

## Review findings folded in (dev + security review, 2026-06-21)

| # | Finding | Severity | Resolution in this plan |
|---|---------|----------|-------------------------|
| C1 | rubygems/gomod test files are **white-box** (`package rubygems` / `package gomod`); npm's helper/tests are black-box (`package npm_test`). Copying them verbatim won't compile. | CRITICAL | New multi-index tests go in **separate files** declared `package rubygems_test` / `package gomod_test` (Go allows both in one dir), so the npm-style package-qualified snippets compile unchanged. Tasks 3/4/7 say so explicitly. |
| C2 | `idx.URLOrDefault(a.upstream)` — a method on `adapter.ResolvedIndex` cannot be defined in package `rubygems`. | CRITICAL | Use the `idxURL(idx)` **adapter method** pattern (already specified for gomod) in rubygems too. `URLOrDefault` removed. |
| S1 | **RubyGems compact index `/info/{name}` is what modern Bundler uses** and was left unhandled/default-only → a scoped private name could resolve to public (dependency confusion) or be undiscoverable. | CRITICAL | **Add `/info/{name}` fan-out** (relay-only — `/info` carries checksums, no download URL) with the same scoped-miss 404+audit. Whole-index files (`/versions`, `/names`, `/specs*.4.8.gz`, `/quick/Marshal.4.8/*`, `/api/v1/dependencies`) stay **default-only** and **cannot enumerate private gems** — an inherent limitation of the settled ordered-fallback (non-merge) strategy, documented in Task 11. The per-name endpoints (`/info/{name}`, `/api/v1/gems/{name}.json`) + the download-leg re-resolution are what close the dependency-confusion hole. The E2E **must drive a real `gem install` of the private gem** (not just `curl`) to prove resolution + scan+cache. |
| S5 | Flat-namespace download recovery (`firstIndexFor` by name) cannot recover an **unscoped** extra index → a gem/module from an unscoped extra index would be re-fetched from the default on download (content substitution). | HIGH | **Extra indexes for rubygems/gomod MUST be `packages`-scoped** (mirrors npm/nuget). Documented as a hard limitation in Tasks 5/8/11; the e2e fixtures are scoped. |
| S6 | Per-index credentials must never leak on a malicious cross-host download redirect. | MEDIUM | Both adapters' download `httpClient` switches to `NewRedirectSafeClient`. Tasks 4/7 add a **hard test**: a 302-to-foreign-host download asserts the `Authorization` header is absent on the second hop. |
| S7 | `gem_uri` fail-closed could be evaded by relative / scheme-relative URLs, or a download URL in a non-`gem_uri` field. | MEDIUM | `proxyRewriteDownloadURL` already fails closed on non-absolute / non-http(s) (relative + `//host` → no scheme → refused); Task 1 **adds explicit tests** for both forms. `gem_uri` is documented as RubyGems' sole download field; the helper rewrites only it (any future per-version download field would need the same treatment — noted). |
| S8 | gomod metadata relay had **no size cap** → unbounded body from a low-trust extra GOPROXY (DoS). | MEDIUM | gomod `tryServeMetadata` caps with `io.LimitReader` (a few MB) and fails closed on exceed (Task 7). |
| S9 | Extra-index header allowlist duplicated across handlers — drift risk. | LOW | One shared `relayExtraIndexHeaders` helper per adapter; noted in Tasks 3/7. |
| I3 | gomod `modulePath` contains `/` — must NOT pass through `ValidatePackageName`. | IMPORTANT | gomod fan-out uses `parsed.modulePath` directly (as the existing code does); Task 7 states this explicitly. |
| M1 | `scanner.CanonicalPackageName` does **not** lowercase `go`/`rubygems` (only pypi/nuget). | (confirms plan) | Glob scopes match the case-sensitive decoded path/name verbatim; Task 6's hedge dropped. |

---

## File structure

- **Modify:** `internal/adapter/upstream_set.go` — add `RewriteRubyGemsGemURI` (fail-closed `gem_uri` rewrite) + unit tests. (Reuses the existing `downloadHostSet` / `proxyRewriteDownloadURL` helpers from Phase 5.)
- **Modify:** `internal/adapter/upstream_set_test.go` — helper unit tests.
- **Modify:** `internal/adapter/rubygems/rubygems.go` — constructor takes `config.UpstreamSet`; resolver field; per-gem metadata fan-out; download index recovery + namespaced IDs + auth; scoped-miss audit.
- **Modify:** `internal/adapter/rubygems/rubygems_test.go` — migrate setup to the new constructor; add multi-index unit tests.
- **Modify:** `internal/adapter/gomod/gomod.go` — constructor takes `config.UpstreamSet`; resolver field; per-module metadata fan-out; download index recovery + namespaced IDs + auth; scoped-miss audit.
- **Modify:** `internal/adapter/gomod/gomod_test.go` — same.
- **Modify:** `cmd/shieldoo-gate/main.go` — pass `cfg.Upstreams.RubyGems` / `cfg.Upstreams.GoMod` (UpstreamSet) to the constructors; drop the now-unused `rubygemsUpstream` / `gomodUpstream` strings.
- **Modify:** `config.example.yaml` — rubygems + gomod multi-index schema blocks.
- **Create:** `examples/rubygems-private-source/`, `examples/gomod-private-proxy/`.
- **Modify (config migration):** `docker/config.yaml`, `examples/deploy/config.yaml`, `.deploy/config.yaml` (if present), Helm `values.yaml` + `configmap.yaml` — restructure `rubygems`/`gomod` to the `default:` form (shape-only; no prod `extra_indexes`).
- **Create:** `tests/e2e-shell/fixtures/private-index/gen-rubygems-gomod.sh` + committed `www/` subtrees; `tests/e2e-shell/test_rubygems_multi_index.sh`, `tests/e2e-shell/test_gomod_multi_index.sh`.
- **Modify:** `tests/e2e-shell/config.e2e.yaml` (wire rubygems/gomod multi-index), `tests/e2e-shell/fixtures/private-index/Caddyfile` (serve the gem + go-module trees), `tests/e2e-shell/run.sh` + `run_all.sh` (register the two new tests).
- **Modify:** `docs/adapters.md` — RubyGems + Go modules "Multi-Upstream Indexes" sections; `docs/development/e2e-testing.md` — extend the scenario matrix.

Depends on Phase 1 (`config.UpstreamSet`), Phase 2 (`adapter.UpstreamResolver`), Phase 3 (reference pattern), Phase 4 (E2E harness), Phase 5 (npm/nuget download-leg pattern + shared helpers).

---

## Task 1: Shared fail-closed `gem_uri` rewrite helper (RubyGems)

**Files:**
- Modify: `internal/adapter/upstream_set.go`
- Test: `internal/adapter/upstream_set_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/adapter/upstream_set_test.go`:

```go
func TestRewriteRubyGemsGemURI_RewritesServingHost(t *testing.T) {
	in := []byte(`{"name":"mycompany-gem","version":"1.0.0",` +
		`"gem_uri":"https://gems.corp.example.com/gems/mycompany-gem-1.0.0.gem",` +
		`"homepage_uri":"https://corp.example.com/","sha":"abc"}`)
	out, err := RewriteRubyGemsGemURI(in,
		ResolvedIndex{Name: "corp", URL: "https://gems.corp.example.com"},
		"http://gate.local")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `"gem_uri":"http://gate.local/gems/mycompany-gem-1.0.0.gem"`)
	assert.Contains(t, s, `"sha":"abc"`)                          // integrity preserved
	assert.Contains(t, s, `"homepage_uri":"https://corp.example.com/"`) // non-download URL untouched
}

func TestRewriteRubyGemsGemURI_ForeignHost_FailsClosed(t *testing.T) {
	in := []byte(`{"gem_uri":"https://evil.cdn.example.net/gems/x-1.0.0.gem"}`)
	_, err := RewriteRubyGemsGemURI(in,
		ResolvedIndex{Name: "corp", URL: "https://gems.corp.example.com"}, "http://gate.local")
	require.Error(t, err)
}

func TestRewriteRubyGemsGemURI_NoGemURI_PassesThrough(t *testing.T) {
	in := []byte(`{"name":"x","version":"1.0.0"}`)
	out, err := RewriteRubyGemsGemURI(in,
		ResolvedIndex{Name: "corp", URL: "https://gems.corp.example.com"}, "http://gate.local")
	require.NoError(t, err)
	assert.JSONEq(t, string(in), string(out))
}

func TestRewriteRubyGemsGemURI_InvalidJSON_FailsClosed(t *testing.T) {
	_, err := RewriteRubyGemsGemURI([]byte(`not json`),
		ResolvedIndex{Name: "corp", URL: "https://gems.corp.example.com"}, "http://gate.local")
	require.Error(t, err)
}

// S7 — relative and scheme-relative gem_uri values must fail closed (they have no
// host/scheme to validate, so proxyRewriteDownloadURL refuses them).
func TestRewriteRubyGemsGemURI_RelativeURI_FailsClosed(t *testing.T) {
	in := []byte(`{"gem_uri":"/gems/x-1.0.0.gem"}`)
	_, err := RewriteRubyGemsGemURI(in,
		ResolvedIndex{Name: "corp", URL: "https://gems.corp.example.com"}, "http://gate.local")
	require.Error(t, err)
}

func TestRewriteRubyGemsGemURI_SchemeRelativeForeign_FailsClosed(t *testing.T) {
	in := []byte(`{"gem_uri":"//evil.cdn/x-1.0.0.gem"}`)
	_, err := RewriteRubyGemsGemURI(in,
		ResolvedIndex{Name: "corp", URL: "https://gems.corp.example.com"}, "http://gate.local")
	require.Error(t, err)
}
```

Run: `go test ./internal/adapter/ -run 'RewriteRubyGemsGemURI' -v` → FAIL (undefined helper).

- [ ] **Step 2: Implement the helper**

Add to `internal/adapter/upstream_set.go` (`encoding/json`, `fmt`, `net/url`, `strings` are already imported from Phase 5):

```go
// RewriteRubyGemsGemURI rewrites the gem_uri download field of an EXTRA-index
// RubyGems /api/v1/gems/{name}.json document so a client that follows gem_uri
// (e.g. `gem fetch`) is routed through the proxy's scan pipeline. It is
// JSON-aware so it can FAIL CLOSED if gem_uri's host is neither the serving
// index host nor its configured files host (serving such a doc would let a
// client fetch the .gem directly, bypassing the scan), or if the body is not
// valid JSON. Non-download URLs (homepage_uri, project_uri, …) are untouched.
// Docs WITHOUT a gem_uri pass through unchanged. The DEFAULT index is NOT handled
// here (it keeps the verbatim relay, byte-identical to today).
func RewriteRubyGemsGemURI(body []byte, idx ResolvedIndex, proxyOrigin string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("upstream: index %q rubygems metadata is not valid JSON (cannot rewrite, refusing to serve): %w", idx.Name, err)
	}
	gu, ok := doc["gem_uri"].(string)
	if !ok || gu == "" {
		return body, nil // nothing to rewrite; relay verbatim
	}
	allowed := downloadHostSet(idx)
	rewritten, err := proxyRewriteDownloadURL(gu, idx.Name, allowed, proxyOrigin)
	if err != nil {
		return nil, err
	}
	doc["gem_uri"] = rewritten
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("upstream: index %q rubygems metadata re-marshal: %w", idx.Name, err)
	}
	return out, nil
}
```

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/ -run 'RewriteRubyGemsGemURI|downloadHostSet' -v && go build ./...
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go
git commit -m "feat(upstream): fail-closed rubygems gem_uri rewrite helper"
```

---

## Task 2: RubyGems — resolver wiring (default-only behaviour unchanged)

**Files:**
- Modify: `internal/adapter/rubygems/rubygems.go` (struct ~37-45, constructor ~47-65)
- Modify: `cmd/shieldoo-gate/main.go` (~500, ~529)
- Test: `internal/adapter/rubygems/rubygems_test.go` (setup helper)

- [ ] **Step 1: Migrate the test setup helper to the new constructor (failing)**

In `internal/adapter/rubygems/rubygems_test.go`, find every `NewRubyGemsAdapter(` call and change the upstream argument from a bare string to an `UpstreamSet`:

```go
a := rubygems.NewRubyGemsAdapter(db, cacheStore, scanEngine, policyEngine,
	config.UpstreamSet{Default: upstream.URL})
```

(Add `"github.com/cloudfieldcz/shieldoo-gate/internal/config"` to the test imports if not present.)

Run: `go test ./internal/adapter/rubygems/ -count=1` → FAIL to compile (constructor still wants a string).

- [ ] **Step 2: Change the struct + constructor**

In `internal/adapter/rubygems/rubygems.go`, add `resolver` and accept an `UpstreamSet`:

```go
type RubyGemsAdapter struct {
	db           *config.GateDB
	cache        cache.CacheStore
	scanEngine   *scanner.Engine
	policyEngine *policy.Engine
	upstream     string // default index base (back-compat; == resolver default)
	resolver     *adapter.UpstreamResolver
	router       http.Handler
	httpClient   *http.Client
}

// NewRubyGemsAdapter creates and wires a RubyGemsAdapter.
func NewRubyGemsAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreams config.UpstreamSet,
) *RubyGemsAdapter {
	defaultURL := upstreams.DefaultOr("https://rubygems.org")
	resolver, err := adapter.NewUpstreamResolver("rubygems", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		panic(fmt.Sprintf("rubygems: building upstream resolver: %v", err))
	}
	a := &RubyGemsAdapter{
		db:           db,
		cache:        cacheStore,
		scanEngine:   scanEngine,
		policyEngine: policyEngine,
		upstream:     strings.TrimRight(defaultURL, "/"),
		resolver:     resolver,
		httpClient:   adapter.NewRedirectSafeClient(5 * time.Minute), // redirect-safe: strips auth on cross-host redirect
	}
	a.router = a.buildRouter()
	return a
}
```

> The `httpClient` switches from `NewProxyHTTPClient` to `NewRedirectSafeClient` (a superset — same timeout, adds cross-host/scheme auth-strip) because the download leg now forwards per-index credentials. Verify the existing download tests still pass.

- [ ] **Step 3: Update `main.go`**

In `cmd/shieldoo-gate/main.go`, drop the `rubygemsUpstream := …DefaultOr(…)` line and pass the set:

```go
rubygemsAdapter := rubygems.NewRubyGemsAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.RubyGems)
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/adapter/rubygems/ -v && go build ./...
git add internal/adapter/rubygems/rubygems.go internal/adapter/rubygems/rubygems_test.go cmd/shieldoo-gate/main.go
git commit -m "feat(rubygems): wire UpstreamResolver (default-only behaviour unchanged)"
```

Expected: all existing rubygems tests PASS (default path unchanged), build clean.

---

## Task 3: RubyGems — per-gem metadata fan-out + scoped-miss audit

**Files:**
- Modify: `internal/adapter/rubygems/rubygems.go` (router + a new `serveMetadataFanOut`)
- Test: `internal/adapter/rubygems/rubygems_test.go`

> **Scope (revised per security review S1):** the **per-name** endpoints fan out (they carry `{name}` and so honour scoping + scoped-miss):
> - `/api/v1/gems/{name}.json` — `gem` CLI; **rewrites `gem_uri` fail-closed** for extra indexes.
> - `/api/v1/versions/{name}.json` — relay (no download URL).
> - `/info/{name}` — **modern Bundler's compact index** (NEW route); relay-only (`/info` carries per-version checksums but **no** download URL, like gomod metadata). Fanning this out is what closes the dependency-confusion hole the review found (a scoped name resolves only to its claiming index, never public).
>
> The **whole-index / multi-name / legacy** endpoints stay on `handlePassThrough` (default-only) and **cannot enumerate private gems** — an inherent limitation of the settled ordered-fallback (non-merge) strategy: `/versions`, `/names` (compact index master files), `/specs*.4.8.gz`, `/quick/Marshal.4.8/*`, and `/api/v1/dependencies` (left unimplemented → 404, forcing clients to the per-name path). Documented in Task 11. The download leg (`/gems/`) always re-resolves by name + scans, so this is a *discoverability* limitation, not a scan bypass.
>
> **Test package (per dev review C1):** put the new multi-index tests in a NEW file `internal/adapter/rubygems/rubygems_multi_index_test.go` declared `package rubygems_test` (black-box), so the npm-style package-qualified helper/test code below compiles unchanged alongside the existing white-box `rubygems_test.go`.

- [ ] **Step 1: Add the `proxyOrigin` helper** near the handlers (mirror npm):

```go
func proxyOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
```

- [ ] **Step 2: Write failing tests**

Create `internal/adapter/rubygems/rubygems_multi_index_test.go` declared `package rubygems_test` (black-box — see C1) with the imports the npm black-box test uses (`config`, `local`, `policy`, `scanner`, `adapter`, `rubygems`, `httptest`, testify). Add a multi-index helper + tests (mirror `newMultiIndexNPM`):

```go
func newMultiIndexRubyGems(t *testing.T, defaultURL string, extras []config.UpstreamIndex) *rubygems.RubyGemsAdapter {
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
	return rubygems.NewRubyGemsAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: defaultURL, ExtraIndexes: extras})
}

func TestRubyGemsAdapter_ExtraIndexMetadata_RewritesGemURI(t *testing.T) {
	var corp *httptest.Server
	corp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/gems/mycompany-gem.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"mycompany-gem","version":"1.0.0","gem_uri":"` +
				corp.URL + `/gems/mycompany-gem-1.0.0.gem"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexRubyGems(t, "https://rubygems.invalid",
		[]config.UpstreamIndex{{Name: "private", URL: corp.URL, Packages: []string{"mycompany-*"}}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gems/mycompany-gem.json", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `/gems/mycompany-gem-1.0.0.gem`)
	assert.NotContains(t, rec.Body.String(), corp.URL) // serving-host origin rewritten away
}

func TestRubyGemsAdapter_ScopedMiss_Returns404(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexRubyGems(t, "https://rubygems.invalid",
		[]config.UpstreamIndex{{Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"}}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gems/mycompany-ghost.json", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRubyGemsAdapter_ExtraIndexForeignGemURI_FailsClosed(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/gems/mycompany-gem.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"gem_uri":"https://evil.cdn/x-1.0.0.gem"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexRubyGems(t, "https://rubygems.invalid",
		[]config.UpstreamIndex{{Name: "private", URL: corp.URL, Packages: []string{"mycompany-*"}}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/gems/mycompany-gem.json", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code) // fail closed
}
```

Run: `go test ./internal/adapter/rubygems/ -run 'ExtraIndex|ScopedMiss' -v` → FAIL.

- [ ] **Step 3: Implement the fan-out**

In `rubygems.go`, change the two per-gem JSON routes to a new handler and add the fan-out. Update `buildRouter`:

```go
	// Per-gem metadata — fan out across indexes (rewrites gem_uri fail-closed for extra indexes).
	r.Get("/api/v1/gems/{name}.json", a.handleGemMetadata)
	r.Get("/api/v1/versions/{name}.json", a.handleVersionsMetadata)
	// Compact index (modern Bundler) — per-gem, relay-only, fans out. (S1 fix.)
	r.Get("/info/{name}", a.handleInfo)
```

Add the handlers + fan-out (mirrors npm's `serveMetadataFanOut`/`tryServeMetadata`):

```go
func (a *RubyGemsAdapter) handleGemMetadata(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name", Reason: err.Error()})
		return
	}
	a.serveMetadataFanOut(w, r, name, "/api/v1/gems/"+name+".json", true) // rewrite gem_uri
}

func (a *RubyGemsAdapter) handleVersionsMetadata(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name", Reason: err.Error()})
		return
	}
	a.serveMetadataFanOut(w, r, name, "/api/v1/versions/"+name+".json", false) // no download URL → no rewrite
}

// handleInfo serves the compact-index per-gem file (modern Bundler). It carries
// per-version numbers + checksums but NO download URL, so it is relay-only — the
// value is in fanning it out (a scoped name resolves only to its claiming index).
func (a *RubyGemsAdapter) handleInfo(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := adapter.ValidatePackageName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name", Reason: err.Error()})
		return
	}
	a.serveMetadataFanOut(w, r, name, "/info/"+name, false) // no download URL → no rewrite
}

// serveMetadataFanOut tries each resolved index for the gem's metadata, serving
// the first that has it (200). The default index relays verbatim (byte-identical
// to today). Extra indexes relay an allowlist of headers and, when rewriteGemURI
// is set, rewrite gem_uri fail-closed (502 on a foreign host / non-JSON). A
// claimed-namespace miss → 404 + audit.
func (a *RubyGemsAdapter) serveMetadataFanOut(w http.ResponseWriter, r *http.Request, name, path string, rewriteGemURI bool) {
	for _, idx := range a.resolver.ResolveForPackage(name) {
		served, err := a.tryServeMetadata(w, r, idx, path, rewriteGemURI)
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
	if claimants := a.resolver.ClaimingIndexNames(name); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemRubyGems), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, name),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index gem not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	adapter.WriteJSONError(w, http.StatusNotFound, adapter.ErrorResponse{Error: "not found", Artifact: name})
}

// tryServeMetadata fetches one index's metadata at path. (true,nil)=served;
// (false,nil)=404; (false,err)=transport/non-200/rewrite error. A rewrite
// failure for an EXTRA index is FAIL CLOSED: writes 502, returns (true,nil).
func (a *RubyGemsAdapter) tryServeMetadata(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, path string, rewriteGemURI bool) (bool, error) {
	target := strings.TrimRight(idx.URL, "/") + path
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
		return false, fmt.Errorf("rubygems: index %q returned %d", idx.Name, resp.StatusCode)
	}
	const maxMetadataSize = 64 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("rubygems: index %q metadata exceeds size limit", idx.Name)
	}

	out := body
	if idx.Name != "" && rewriteGemURI {
		rewritten, rerr := adapter.RewriteRubyGemsGemURI(body, idx, proxyOrigin(r))
		if rerr != nil {
			log.Error().Err(rerr).Str("index", idx.Name).Msg("SECURITY: rubygems gem_uri rewrite failed, refusing to serve")
			http.Error(w, "upstream metadata could not be safely rewritten", http.StatusBadGateway)
			return true, nil
		}
		out = rewritten
	}
	relayMetadataHeaders(w, resp, idx.Name)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
	return true, nil
}

// relayMetadataHeaders copies upstream headers. Extra (low-trust) indexes get an
// allowlist only; the default index relays all (minus Content-Length).
func relayMetadataHeaders(w http.ResponseWriter, resp *http.Response, indexName string) {
	if indexName != "" {
		for _, h := range []string{"Content-Type", "ETag", "Last-Modified"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}
		return
	}
	for key, vals := range resp.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
}
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/adapter/rubygems/ -v && go build ./...
git add internal/adapter/rubygems/rubygems.go internal/adapter/rubygems/rubygems_test.go
git commit -m "feat(rubygems): per-gem metadata fan-out + fail-closed gem_uri rewrite + scoped-miss audit"
```

---

## Task 4: RubyGems — download index recovery + namespaced artifact IDs + auth

**Files:**
- Modify: `internal/adapter/rubygems/rubygems.go` (`handleGemDownload`, `downloadScanServe`, `rubygemsArtifactID`)
- Test: `internal/adapter/rubygems/rubygems_test.go`

> **Index recovery (design):** the `/gems/{filename}` route carries the gem name (parsed from the filename), so recover the serving index by re-resolving the name and taking the first resolved index (deterministic per gem). No new route.

- [ ] **Step 1: Add the test-only DB accessor** to `rubygems.go` if absent:

```go
// DB exposes the adapter's database handle for tests.
func (a *RubyGemsAdapter) DB() *config.GateDB { return a.db }
```

- [ ] **Step 2: Write the failing test**

```go
func TestRubyGemsAdapter_ExtraIndexGemDownload_ScansAndNamespaces(t *testing.T) {
	var sentAuth string
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/gems/mycompany-gem-1.0.0.gem" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("dummy-gem-bytes"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_RUBY_CORP_TOK", "tok-xyz")
	a := newMultiIndexRubyGems(t, "https://rubygems.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_RUBY_CORP_TOK"},
	}})
	req := httptest.NewRequest(http.MethodGet, "/gems/mycompany-gem-1.0.0.gem", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code) // no scanners → clean → served
	assert.Equal(t, "Bearer tok-xyz", sentAuth)
	status, err := adapter.GetArtifactStatus(a.DB(), "rubygems__corp:mycompany-gem:1.0.0:mycompany-gem-1.0.0.gem")
	require.NoError(t, err)
	require.NotNil(t, status)
}

// S6 — a malicious cross-host download redirect must NOT carry the per-index
// credential to the redirect target (NewRedirectSafeClient strips it).
func TestRubyGemsAdapter_DownloadRedirectToForeignHost_StripsAuth(t *testing.T) {
	var foreignAuth string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("dummy-gem-bytes"))
	}))
	t.Cleanup(foreign.Close)
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+r.URL.Path, http.StatusFound) // 302 to a different host
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_RUBY_CORP_TOK", "tok-secret")
	a := newMultiIndexRubyGems(t, "https://rubygems.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_RUBY_CORP_TOK"},
	}})
	req := httptest.NewRequest(http.MethodGet, "/gems/mycompany-gem-1.0.0.gem", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Empty(t, foreignAuth, "Authorization must be stripped on cross-host redirect")
}
```

- [ ] **Step 3: Recover the index on download + namespace**

Add `firstIndexFor` (mirror npm) to `rubygems.go`:

```go
// firstIndexFor recovers the serving index for a download by re-resolving the
// gem name (the /gems/ route carries the name). Returns the default index when
// resolution is empty (a scoped-miss download: the fetch then 404s on the absent
// upstream — correct, no public fallback).
func (a *RubyGemsAdapter) firstIndexFor(name string) adapter.ResolvedIndex {
	if idxs := a.resolver.ResolveForPackage(name); len(idxs) > 0 {
		return idxs[0]
	}
	return adapter.ResolvedIndex{} // default
}
```

Change `rubygemsArtifactID` to be eco-aware (keep a thin back-compat wrapper if other callers exist — grep first):

```go
func rubygemsArtifactIDFor(eco, name, version, filename string) string {
	return fmt.Sprintf("%s:%s:%s:%s", eco, name, version, filename)
}
```

In `handleGemDownload`, resolve the index and pass it down. Change the final call from
`a.downloadScanServe(w, r, name, version, filename)` to:

```go
	idx := a.firstIndexFor(name)
	a.downloadScanServe(w, r, idx, name, version, filename)
```

In `downloadScanServe`, add `idx adapter.ResolvedIndex` as the third parameter and:
- compute the namespaced eco + artifact ID at the top:
  ```go
  eco := adapter.NamespacedEcosystem(string(scanner.EcosystemRubyGems), idx.Name)
  artifactID := rubygemsArtifactIDFor(eco, name, version, filename)
  ```
  (replace the existing `artifactID := rubygemsArtifactID(name, version, filename)`);
- build the upstream URL from the resolved index instead of `a.upstream`, via an **adapter method** `idxURL` (C2 — a method on `adapter.ResolvedIndex` cannot live in package `rubygems`):
  ```go
  // idxURL returns the index URL, falling back to the default upstream for the
  // default index (empty Name/URL).
  func (a *RubyGemsAdapter) idxURL(idx adapter.ResolvedIndex) string {
  	if idx.URL != "" {
  		return idx.URL
  	}
  	return a.upstream
  }
  ```
  ```go
  upstreamURL, err := url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), "gems", filename)
  ```
- thread the per-index auth into the download by switching the download call to the authed variant:
  ```go
  tmpPath, size, sha, err := downloadToTempAuthed(pctx, upstreamURL, a.resolver.AuthHeader(idx), a.httpClient)
  ```
- keep `scanArtifact.Ecosystem = scanner.EcosystemRubyGems` (the **bare** eco — the cache/SBOM key uses the namespaced `artifactID`; the scanner eco stays canonical for typosquat/version-diff semantics, matching npm/nuget).

Add `downloadToTempAuthed` to `rubygems.go` (copy npm's: sets `Authorization` when non-empty; uses the redirect-safe `a.httpClient`). Replace the existing `downloadToTemp` caller; keep `downloadToTemp` only if another caller remains (grep).

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/adapter/rubygems/ -v && go build ./...
git add internal/adapter/rubygems/rubygems.go internal/adapter/rubygems/rubygems_test.go
git commit -m "feat(rubygems): download index recovery (re-resolve) + namespaced artifact IDs + per-index auth"
```

---

## Task 5: RubyGems — config.example.yaml + example project

**Files:**
- Modify: `config.example.yaml`
- Create: `examples/rubygems-private-source/README.md`, `examples/rubygems-private-source/Gemfile.example`

- [ ] **Step 1:** Add a `rubygems` multi-index block to `config.example.yaml` mirroring the npm one (default + scoped private source with env-var `auth`; note `files_host` is **PyPI-only** and rejected for rubygems).
- [ ] **Step 2:** `examples/rubygems-private-source/README.md` documenting: configure `upstreams.rubygems.extra_indexes` with a scoped private source (env-var auth), point the `Gemfile`'s `source` at the gate, `bundle install` the private gem **through** the gate (scanned + cached under `rubygems__<index>`, not bypassed). `Gemfile.example`:
  ```ruby
  source "http://localhost:8086"
  gem "mycompany-gem"
  ```
  Reference `tests/e2e-shell/test_rubygems_multi_index.sh` as the executable spec. Add to `examples/README.md`.
- [ ] **Step 3:** Verify + commit:

```bash
make build && make lint && make test
git add config.example.yaml examples/rubygems-private-source/ examples/README.md
git commit -m "docs(rubygems): document multi-index config + private-source example"
```

---

## Task 6: Go modules — resolver wiring (default-only behaviour unchanged)

Mirror **Task 2** for `internal/adapter/gomod/gomod.go`:

- [ ] **Step 1:** In `internal/adapter/gomod/gomod_test.go`, change every `NewGoModAdapter(` call's upstream arg to `config.UpstreamSet{Default: upstream.URL}` (add the `config` import if needed). Run → FAIL to compile.
- [ ] **Step 2:** Struct gains `resolver *adapter.UpstreamResolver`; constructor accepts `config.UpstreamSet`, computes `defaultURL := upstreams.DefaultOr("https://proxy.golang.org")`, builds `adapter.NewUpstreamResolver("go", config.UpstreamSet{Default: defaultURL, ExtraIndexes: upstreams.ExtraIndexes})` (panic on err), sets `upstream: strings.TrimRight(defaultURL,"/")`, and switches `httpClient` to `adapter.NewRedirectSafeClient(5 * time.Minute)`.

  > **Verify the ecosystem string** the resolver is built with matches the scanner constant: `scanner.EcosystemGo == "go"` (confirmed at `internal/scanner/interface.go:17`). Pass the literal `"go"`.

- [ ] **Step 3:** `main.go`: drop `gomodUpstream := …`, pass `cfg.Upstreams.GoMod`:
  ```go
  gomodAdapter := gomod.NewGoModAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.GoMod)
  ```
- [ ] **Step 4:** Run + commit:

```bash
go test ./internal/adapter/gomod/ -v && go build ./...
git add internal/adapter/gomod/gomod.go internal/adapter/gomod/gomod_test.go cmd/shieldoo-gate/main.go
git commit -m "feat(gomod): wire UpstreamResolver (default-only behaviour unchanged)"
```

Expected: all existing gomod tests PASS, build clean.

> **Case-sensitivity (confirmed, review M1):** `scanner.CanonicalPackageName` lowercases only `pypi`/`nuget` — for `go` (and `rubygems`) it returns the name verbatim (`internal/scanner/canonicalname.go`). Go module paths are therefore matched case-sensitively against the **decoded** path (the adapter decodes the GOPROXY bang-encoding before resolving), so glob scopes are written in true decoded case, e.g. `github.com/mycompany/*`. No limitation needed.

---

## Task 7: Go modules — per-module metadata fan-out + download index recovery + namespaced IDs + auth

**Files:**
- Modify: `internal/adapter/gomod/gomod.go` (`handleRequest`, `proxyPassThrough` → fan-out, `downloadScanServe`)
- Test: `internal/adapter/gomod/gomod_test.go`

> **No rewrite:** GOPROXY metadata carries no download URLs, so the fan-out relays each index's `.info`/`.mod`/`list`/`@latest` **verbatim** (size-capped — S8) — the only change vs today is *which* index is queried (resolve by module path) + the scoped-miss 404/audit. The `.zip` download recovers the index by re-resolution + namespaces + auths.
>
> **I3 caution:** a Go module path contains `/` (`github.com/mycompany/lib`). Resolve/audit on `parsed.modulePath` **directly** — do **not** run it through `adapter.ValidatePackageName` (which rejects `/`). The existing handler already does this; the fan-out preserves it. (Unlike the rubygems `{name}` handlers, which DO validate, because gem names have no `/`.)

- [ ] **Step 1: Write failing tests** in a NEW file `internal/adapter/gomod/gomod_multi_index_test.go` declared `package gomod_test` (black-box — C1; the existing `gomod_test.go` is white-box `package gomod`). `newMultiIndexGoMod` helper (mirror `newMultiIndexNPM`, returns `*gomod.GoModAdapter`); then:

```go
func TestGoModAdapter_ExtraIndexInfo_FansOut(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/github.com/mycompany/lib/@v/v1.0.0.info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexGoMod(t, "https://proxy.invalid",
		[]config.UpstreamIndex{{Name: "corp", URL: corp.URL, Packages: []string{"github.com/mycompany/*"}}})
	req := httptest.NewRequest(http.MethodGet, "/github.com/mycompany/lib/@v/v1.0.0.info", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"Version":"v1.0.0"`)
}

func TestGoModAdapter_ScopedMiss_Returns404(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexGoMod(t, "https://proxy.invalid",
		[]config.UpstreamIndex{{Name: "corp", URL: corp.URL, Packages: []string{"github.com/mycompany/*"}}})
	req := httptest.NewRequest(http.MethodGet, "/github.com/mycompany/ghost/@v/list", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGoModAdapter_ExtraIndexZipDownload_ScansAndNamespaces(t *testing.T) {
	var sentAuth string
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentAuth = r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/@v/v1.0.0.zip") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("PK\x03\x04dummy-zip"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_GO_CORP_TOK", "tok-xyz")
	a := newMultiIndexGoMod(t, "https://proxy.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"github.com/mycompany/*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_GO_CORP_TOK"},
	}})
	req := httptest.NewRequest(http.MethodGet, "/github.com/mycompany/lib/@v/v1.0.0.zip", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Bearer tok-xyz", sentAuth)
	status, err := adapter.GetArtifactStatus(a.DB(), "go__corp:github.com/mycompany/lib:v1.0.0")
	require.NoError(t, err)
	require.NotNil(t, status)
}
```

Add `func (a *GoModAdapter) DB() *config.GateDB { return a.db }` if absent.

Also add a gomod analogue of the rubygems **S6** test (`TestGoModAdapter_DownloadRedirectToForeignHost_StripsAuth`): the `corp` server 302-redirects the `.zip` to a foreign host; assert the foreign host receives an **empty** `Authorization` header (the `NewRedirectSafeClient` strips it cross-host).

- [ ] **Step 2: Implement the fan-out + index recovery**

Add `firstIndexFor` (mirror npm/rubygems, keyed on `parsed.modulePath`):

```go
func (a *GoModAdapter) firstIndexFor(modulePath string) adapter.ResolvedIndex {
	if idxs := a.resolver.ResolveForPackage(modulePath); len(idxs) > 0 {
		return idxs[0]
	}
	return adapter.ResolvedIndex{} // default
}
```

Replace the dispatch tail of `handleRequest` so metadata fans out and the zip leg recovers the index:

```go
	switch parsed.reqType {
	case reqZipDownload:
		idx := a.firstIndexFor(parsed.modulePath)
		a.downloadScanServe(w, r, idx, parsed, rawPath)
	default:
		// list, info, mod, latest — fan out across indexes (verbatim relay; no URLs to rewrite)
		a.serveMetadataFanOut(w, r, parsed.modulePath, rawPath)
	}
```

Add the fan-out (verbatim relay; default relays all headers, extra indexes relay an allowlist):

```go
func (a *GoModAdapter) serveMetadataFanOut(w http.ResponseWriter, r *http.Request, modulePath, rawPath string) {
	for _, idx := range a.resolver.ResolveForPackage(modulePath) {
		served, err := a.tryServeMetadata(w, r, idx, rawPath)
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
	if claimants := a.resolver.ClaimingIndexNames(modulePath); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemGo), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, modulePath),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index module not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (a *GoModAdapter) tryServeMetadata(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, rawPath string) (bool, error) {
	target, err := url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), rawPath)
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
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("gomod: index %q returned %d", idx.Name, resp.StatusCode)
	}
	// S8 — cap the metadata body from a low-trust extra index (GOPROXY .info/.mod/
	// list/@latest are tiny in practice). Read fully so the size guard runs before
	// any bytes reach the client; fail closed on exceed.
	const maxMetadataSize = 16 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("gomod: index %q metadata exceeds size limit", idx.Name)
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

// idxURL returns the index URL, falling back to the default upstream for the
// default index (empty Name/URL).
func (a *GoModAdapter) idxURL(idx adapter.ResolvedIndex) string {
	if idx.URL != "" {
		return idx.URL
	}
	return a.upstream
}
```

In `downloadScanServe`, add `idx adapter.ResolvedIndex` as the third parameter and:
- namespace the eco + artifact ID at the top (replace the existing `artifactID := gomodArtifactID(...)`):
  ```go
  eco := adapter.NamespacedEcosystem(string(scanner.EcosystemGo), idx.Name)
  artifactID := fmt.Sprintf("%s:%s:%s", eco, parsed.modulePath, parsed.version)
  ```
- build the upstream URL from the resolved index: replace `upstreamURL, err := url.JoinPath(a.upstream, rawPath)` with `url.JoinPath(strings.TrimRight(a.idxURL(idx), "/"), rawPath)`;
- thread auth: replace `downloadToTemp(pctx, upstreamURL, a.httpClient)` with `downloadToTempAuthed(pctx, upstreamURL, a.resolver.AuthHeader(idx), a.httpClient)` (add `downloadToTempAuthed` copied from npm, gomod-flavoured temp prefix);
- keep `scanArtifact.Ecosystem = scanner.EcosystemGo` (bare eco) and the existing async-scan `Ecosystem: scanner.EcosystemGo` — only the artifact **ID** is namespaced.

> Update the cached-serve branches (lines ~432-434) so the async re-scan's `scanner.Artifact.ID` uses the namespaced `artifactID` (it already references the local `artifactID` variable — confirm it picks up the new namespaced value since the variable is reassigned at the top).

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/gomod/ -v && go build ./...
git add internal/adapter/gomod/gomod.go internal/adapter/gomod/gomod_test.go
git commit -m "feat(gomod): per-module metadata fan-out + download index recovery + namespaced IDs + per-index auth"
```

---

## Task 8: Go modules — config.example.yaml + example project

**Files:**
- Modify: `config.example.yaml`
- Create: `examples/gomod-private-proxy/README.md`, `examples/gomod-private-proxy/env.example`

- [ ] **Step 1:** Add a `gomod` multi-index block to `config.example.yaml` mirroring npm (default + scoped private GOPROXY with env-var auth; `files_host` rejected for gomod).
- [ ] **Step 2:** `examples/gomod-private-proxy/README.md`: configure `upstreams.gomod.extra_indexes` with a scoped private GOPROXY (env-var auth), set `GOPROXY` + `GONOSUMCHECK`/`GONOSUMDB` (or `GOFLAGS=-insecure` caveat — document that the gate is the single GOPROXY and `GOPRIVATE`/`GONOSUMDB` must cover the private module path so the go client does not consult sum.golang.org), `go get github.com/mycompany/lib` **through** the gate (scanned + cached under `go__<index>`). `env.example`:
  ```bash
  export GOPROXY=http://localhost:8087
  export GONOSUMCHECK=1
  export GOPRIVATE=github.com/mycompany/*
  ```
  Reference `tests/e2e-shell/test_gomod_multi_index.sh`. Add to `examples/README.md`.
- [ ] **Step 3:** Verify + commit:

```bash
make build && make lint && make test
git add config.example.yaml examples/gomod-private-proxy/ examples/README.md
git commit -m "docs(gomod): document multi-index config + private-proxy example"
```

---

## Task 9: Config migration — rubygems/gomod repo configs → `default:` form (Phase 4b parity)

**Files:** `docker/config.yaml`, `examples/deploy/config.yaml`, `.deploy/config.yaml` (skip if gitignored/absent — CI-safe, per Phase 4b precedent), Helm `values.yaml` + `configmap.yaml`.

> Shape-only, **no behaviour change**, **no production `extra_indexes`**. Mirror exactly how Phase 4b/5 migrated `pypi`/`npm`/`nuget`.

- [ ] **Step 1:** In each committed config, change `rubygems: "https://rubygems.org"` → `rubygems:\n  default: "https://rubygems.org"` and `gomod: "https://proxy.golang.org"` → `gomod:\n  default: "https://proxy.golang.org"`.
- [ ] **Step 2:** Run the Phase 4b config-validation regression test (`grep -rn "TestAllCommittedConfigs\|loadAndValidate" internal/config/`) — it must still pass.
- [ ] **Step 3:** Commit: `config(rubygems,gomod): restructure committed upstreams to default: form (multi-index ready)`.

---

## Task 10: E2E harness — private gem + private Go module + multi-index scenarios

**Files:**
- Create: `tests/e2e-shell/fixtures/private-index/gen-rubygems-gomod.sh` + committed `www/` subtrees.
- Modify: `tests/e2e-shell/fixtures/private-index/Caddyfile` (serve the gem + go-module trees).
- Modify: `tests/e2e-shell/config.e2e.yaml` (rubygems + gomod multi-index).
- Create: `tests/e2e-shell/test_rubygems_multi_index.sh`, `tests/e2e-shell/test_gomod_multi_index.sh`.
- Modify: `tests/e2e-shell/run.sh` + `run_all.sh` (register both).

> **Harness reuse:** the shared `private-index` Caddy already serves PyPI/npm/NuGet trees at `https://private-index:8443` over the test CA. Extend its tree + Caddyfile to also serve the gem download + API JSON and the GOPROXY layout. Reuse the CA so the https-only invariant is preserved.

- [ ] **Step 1: RubyGems fixture** — `gen-rubygems-gomod.sh` builds a tiny `mycompany-gem-1.0.0.gem` (a real `gem build` of a 1-file gem, or a minimal valid `.gem` tar) and writes:
  - `www/gems/mycompany-gem-1.0.0.gem` (the artifact),
  - `www/api/v1/gems/mycompany-gem.json` with `gem_uri` = `https://private-index:8443/gems/mycompany-gem-1.0.0.gem` (so the gate rewrites it back to the gate origin),
  - `www/api/v1/gems/mycompany-evil.json` with a **foreign** `gem_uri` host (negative fixture for the 502 test),
  - `www/info/mycompany-gem` — the compact-index per-gem file (Bundler/modern `gem`): a line like `1.0.0 |checksum:<sha256-of-gem>` (carries the version + checksum, **no** download URL). This is what `gem install` actually fetches, so it must exist for the real-client R2 scenario.
  Commit the tree.

- [ ] **Step 2: Go-module fixture** — build `www/github.com/mycompany/lib/@v/`:
  - `list` (text: `v1.0.0`),
  - `v1.0.0.info` (`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`),
  - `v1.0.0.mod` (`module github.com/mycompany/lib\n\ngo 1.21\n`),
  - `v1.0.0.zip` — a valid module zip (entries prefixed `github.com/mycompany/lib@v1.0.0/`, containing `go.mod` + a `.go` file + `LICENSE`).
  Commit the tree. (Go modules have **no** download-URL-in-metadata, so there is no foreign-host negative fixture for gomod — its scoped-miss + namespacing are the security assertions.)

- [ ] **Step 3: Caddyfile + config.e2e.yaml** — extend the Caddyfile so the gem/api/GOPROXY paths are served as static files (the existing `handle { file_server browse }` likely already covers them; verify the `@v/list` and `.info` extensionless/`.info` files serve with a sane content-type). Wire `config.e2e.yaml`:

```yaml
  rubygems:
    default: "https://rubygems.org"
    extra_indexes:
      - name: "private"
        url: "https://private-index:8443"
        packages: ["mycompany-*"]
  gomod:
    default: "https://proxy.golang.org"
    extra_indexes:
      - name: "private"
        url: "https://private-index:8443"
        packages: ["github.com/mycompany/*"]
```

- [ ] **Step 4: test scripts** — `test_rubygems_multi_index.sh` defines `test_rubygems_multi_index()` (sourced; no `set -e`; uses `helpers.sh`). Scenarios:
  - **R1 back-compat:** `GET /api/v1/gems/rake.json` → 200 via default upstream.
  - **R2 release gate:** two parts.
    - **R2a (rewrite + scan+cache):** `curl "$E2E_RUBYGEMS_URL/api/v1/gems/mycompany-gem.json"` → `gem_uri` rewritten to the gate origin (contains the gate host + `/gems/mycompany-gem-1.0.0.gem`, NOT `private-index`); `curl "$E2E_RUBYGEMS_URL/info/mycompany-gem"` → 200 (compact-index fan-out hit); fetch `GET /gems/mycompany-gem-1.0.0.gem` through the gate (HTTP 200); assert an artifact row under ecosystem `rubygems__private` (`api_jq "/api/v1/artifacts?ecosystem=rubygems__private"`). **This is the hard release gate.**
    - **R2b (real client — S1 proof):** drive a real `gem install mycompany-gem --version 1.0.0 --source "$E2E_RUBYGEMS_URL" --install-dir "$tmp/geminstall" --no-document` (skip with `log_skip` if `gem` is not on PATH in the test-runner). This proves the modern client's compact-index resolution path actually routes the private gem through the gate's scan pipeline (not just a `curl` of the JSON endpoint). The R2a artifact-row assertion remains the authoritative gate.
  - **R3 scoped-miss:** `GET /api/v1/gems/mycompany-ghost.json` → 404; assert a `BLOCKED` audit under `rubygems__private:mycompany-ghost`.
  - **R4 foreign-gem_uri fail-closed:** `GET /api/v1/gems/mycompany-evil.json` → 502; **no** artifact row.

  `test_gomod_multi_index.sh` defines `test_gomod_multi_index()`. Scenarios:
  - **M1 back-compat:** `GET /github.com/rs/zerolog/@v/list` → 200 via default.
  - **M2 release gate:** `GET /github.com/mycompany/lib/@v/v1.0.0.info` → 200 (fan-out hit); `GET /github.com/mycompany/lib/@v/v1.0.0.zip` through the gate → 200; assert an artifact row under ecosystem `go__private` for `github.com/mycompany/lib`.
  - **M3 scoped-miss:** `GET /github.com/mycompany/ghost/@v/list` → 404; assert a `BLOCKED` audit under `go__private:github.com/mycompany/ghost`.

- [ ] **Step 5: register** in `run.sh` + `run_all.sh` (source both; call `test_rubygems_multi_index` after `test_rubygems`, `test_gomod_multi_index` after `test_gomod`).

- [ ] **Step 6: run** (logfile convention):

```bash
docker compose -f tests/e2e-shell/docker-compose.e2e.yml build > /tmp/e2e-p6-build.log 2>&1 && \
  SGW_POLICY_MODE=strict docker compose -f tests/e2e-shell/docker-compose.e2e.yml up \
  --abort-on-container-exit --exit-code-from test-runner > /tmp/e2e-p6.log 2>&1; \
  echo "EXIT=$?"; \
  docker compose -f tests/e2e-shell/docker-compose.e2e.yml down -v --remove-orphans >> /tmp/e2e-p6.log 2>&1; \
  grep -E "Multi-Index|RELEASE GATE|R[0-9]:|M[0-9]:|Passed:|Failed:" /tmp/e2e-p6.log
```

Expected: R1–R4 + M1–M3 PASS alongside the existing PyPI/npm/NuGet multi-index + all back-compat suites. **The `rubygems__private` / `go__private` artifact-row assertions are the hard release gate** — if either fails, a private artifact was served without scanning and the phase is NOT done.

- [ ] **Step 7: commit**

```bash
git add tests/e2e-shell/
git commit -m "test(e2e): rubygems + gomod multi-index scenarios (scanned+cached, scoped-miss, fail-closed)"
```

---

## Task 11: Docs + security review

- [ ] **Step 1:** Add a "Multi-Upstream Indexes" section to the RubyGems + Go modules adapter docs in `docs/adapters.md`. Cover: resolution order, scoping, `eco__<index>` namespacing, download index recovery via re-resolution, the RubyGems `gem_uri` fail-closed rewrite, the per-name fan-out endpoints (`/api/v1/gems/{name}.json`, `/api/v1/versions/{name}.json`, `/info/{name}`), and the **limitations**:
  - **Extra indexes MUST be `packages`-scoped** (S5): the flat-namespace download leg recovers the serving index by re-resolving the name, so an *unscoped* extra index cannot be recovered on download → its artifact would be re-fetched from the default. Unscoped extra indexes are unsupported for rubygems/gomod.
  - **Whole-index discovery is default-only** (S1, inherent to the settled no-merge strategy): RubyGems `/versions`, `/names`, `/specs*.4.8.gz`, `/quick/Marshal.4.8/*`, and `/api/v1/dependencies` are not aggregated, so a private gem is **discoverable only by name** (via `/info/{name}` or `/api/v1/gems/{name}.json`) — which is exactly how Bundler/`gem` fetch gems in the dependency graph. This is a discoverability limitation, **not** a scan bypass (the download leg always re-resolves + scans, and the per-name endpoints never fall a claimed name through to public).
  - **Go modules has no metadata rewrite surface** (client constructs `…/@v/{ver}.zip`).
- [ ] **Step 2:** Extend `docs/development/e2e-testing.md` §5.4 scenario matrix with the RubyGems (R1–R4) and Go modules (M1–M3) rows, and §4 inventory with `rubygems_multi_index` / `gomod_multi_index`.
- [ ] **Step 3:** Run the **security-code-review** skill on the rubygems + gomod diff (mandate (d)): confirm (a) the download leg re-resolves to the correct scoped index + namespaces (no public fallback for a claimed name), (b) the RubyGems `gem_uri` fail-closed rewrite (foreign host → 502, non-JSON → 502), (c) no token leak on redirect (redirect-safe client), (d) no header-relay injection from extra indexes, (e) scoped-miss never falls through to public.
- [ ] **Step 4:** Commit docs: `docs(rubygems,gomod): document multi-upstream-index behaviour + limitations`.

---

## Implementation security review (2026-06-21, mandate (d))

A dedicated security review of the **built** rubygems + gomod code: **verdict = Proceed.**
No scan-bypass and no metadata-path dependency-confusion vector found. Confirmed: every
artifact download routes through the unconditional scan pipeline; the RubyGems `gem_uri`
rewrite fails closed (foreign host / non-JSON → 502, incl. relative + `//host`); claimed-name
metadata misses 404 with no public fallback + namespaced audit; per-index auth is env-only and
redirect-safe on **both** the metadata fan-out and the download leg; extra indexes relay a header
allowlist only; metadata bodies are size-capped (rubygems 64 MB, gomod 16 MB); artifact rows are
namespaced `eco__<index>` while the scanner eco stays canonical.

**One bug the review + E2E jointly caught (now fixed):** the persisted artifact-row ecosystem used
the bare eco while the artifact ID was namespaced, so the release-gate API query
(`?ecosystem=rubygems__private`) found nothing even though the artifact was scanned+cached. Fixed by
setting `scanArtifact.Ecosystem = scanner.Ecosystem(eco)` (mirrors npm/nuget `acd36b7`).

**Two MEDIUM findings deferred (shared with the already-shipped npm/nuget adapters — not new
regressions; tracked as follow-ups, not Phase-6 blockers):**

1. **Claimed-name download fallback when all claiming indexes are breaker-open.** If every claiming
   index has an open circuit breaker, `ResolveForPackage` returns empty and `firstIndexFor` falls
   back to the default (public) index for the download. The artifact is still scanned (no bypass),
   but a private name could be satisfied by a public package during a private-index outage. Fix in a
   follow-up across **all four** flat-/namespaced adapters: have the download leg consult
   `ClaimingIndexNames` and refuse (404/410) instead of defaulting.
2. **Unscoped extra index is only WARNed, not rejected.** For flat-namespace ecosystems an unscoped
   extra index cannot be recovered on the download leg. Follow-up: make it a fatal config error
   (affects npm/nuget equally).

## Phase 6 done-when

- [ ] rubygems + gomod default-only config behaves identically to pre-feature on the served (200) path; the only deliberate change is a per-package 404 now returning a JSON/`"not found"` body (status-identical) — all legacy adapter tests green.
- [ ] Per-package metadata resolves across indexes (ordered fallback + glob scoping); first hit serves; RubyGems extra-index `gem_uri` rewrites through the proxy **fail-closed** (foreign host → 502; non-JSON → 502); Go modules metadata relays verbatim (no URL surface).
- [ ] Download legs recover the serving index by re-resolution, carry per-index env-var auth (redirect-safe), and store artifacts under `rubygems__<index>` / `go__<index>`.
- [ ] Scoped-namespace miss → 404 (no public fallback) + namespaced `BLOCKED` audit + `upstream_scoped_miss_total` metric.
- [ ] Committed configs migrated to `default:` form (no prod `extra_indexes`); config-validation regression green.
- [ ] `make build && make lint && make test` green.
- [ ] Extra indexes are `packages`-scoped (unscoped unsupported for these flat-namespace ecosystems — S5); the compact-index `/info/{name}` fans out so modern Bundler/`gem` resolve scoped private gems only from their claiming index (S1).
- [ ] **E2E green, including the new `rubygems__private` / `go__private` scan+cache release-gate assertions, a real `gem install` of the private gem (S1), the RubyGems foreign-`gem_uri` fail-closed negative, and the cross-host-redirect auth-strip tests (S6).**
- [ ] Examples added; docs updated; implementation security review APPROVED.
</content>
