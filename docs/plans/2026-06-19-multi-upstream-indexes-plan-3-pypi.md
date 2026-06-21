# Multi-Upstream Indexes — Phase 3: PyPI Reference Adapter

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the PyPI adapter the reference multi-index implementation: wire the Phase 2 `UpstreamResolver`, fan `/simple/{package}/` across resolved indexes (ordered fallback + scoping), rewrite each serving index's file URLs to a namespaced proxy path, route extra-index downloads through an SSRF-safe `/ext-packages/{index}/*` handler with per-index auth, and namespace artifact IDs via `NamespacedEcosystem`. Prove with an example + e2e that a secondary-index artifact is **scanned + cached, not bypassed**.

**Architecture:** Default-index behaviour is byte-identical to today (`/packages/*`, `files.pythonhosted.org` regex rewrite, bare `pypi:` artifact IDs). Extra indexes get a separate download route `/ext-packages/{index}/*` so they can never collide with PyPI CDN paths. The `/simple/{package}/` handler tries indexes in resolver order; the first to return the package serves it; a scoped-namespace miss returns 404 (no fallback) and is audited. Extra-index file URLs are rewritten via an HTML-parser pass that **fails closed** (502) if it cannot route an absolute download URL through the proxy — a rewrite miss would be a silent scan bypass.

**Tech Stack:** Go 1.25, `github.com/go-chi/chi/v5`, `golang.org/x/net/html` (rewrite; already in `go.mod`), the Phase 2 `adapter.UpstreamResolver`, `net/http/httptest` (unit), shell + pip (e2e).

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

---

## File structure

- **Modify:** `internal/adapter/upstream_set.go` — add `ScopeMatches`, `ClaimingIndexNames`, and the byte-level `RewriteExtraIndexSimplePage` helper.
- **Modify:** `internal/adapter/pypi/pypi.go` — constructor takes `config.UpstreamSet`; resolver field; `/simple/{package}/` fan-out; `/ext-packages/{index}/*` route; threaded `indexContext` through the download pipeline; namespaced artifact IDs.
- **Modify:** `internal/adapter/pypi/pypi_test.go` — migrate `setupTestPyPI` to the new constructor; add multi-index unit tests.
- **Modify:** `cmd/shieldoo-gate/main.go` — pass `cfg.Upstreams.PyPI` (UpstreamSet) to `NewPyPIAdapter`.
- **Create:** `examples/python-private-index/` — example project using a Hexaly-style extra index.
- **Create:** `tests/e2e-shell/test_pypi_multi_index.sh` — e2e proving scan+cache of a secondary-index artifact.
- **Modify:** `tests/e2e-shell/config.e2e.yaml`, `tests/e2e-shell/run_all.sh` — wire the new e2e.
- **Modify:** `docs/` (PyPI adapter page) + `config.example.yaml`.

Depends on Phase 1 (`config.UpstreamSet`) and Phase 2 (`adapter.UpstreamResolver`).

---

## Task 1: Wire the resolver into PyPIAdapter (no behaviour change for default-only)

**Files:**
- Modify: `internal/adapter/pypi/pypi.go` (struct ~31-46, constructor ~48-65)
- Modify: `cmd/shieldoo-gate/main.go` (~503 pypi wiring)
- Test: `internal/adapter/pypi/pypi_test.go` (`setupTestPyPI` ~22-42)

- [ ] **Step 1: Migrate the test setup to the new constructor (failing)**

In `internal/adapter/pypi/pypi_test.go`, change the constructor call inside `setupTestPyPI`:

```go
	a := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: upstream.URL}, config.TagMutabilityConfig{})
	a.SetFilesHost(upstream.URL)
	return a, upstream
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/adapter/pypi/ -run TestPyPIAdapter_Ecosystem -v`
Expected: FAIL to compile — `cannot use config.UpstreamSet{…} (…) as string value` (constructor still wants a string).

- [ ] **Step 0: Add the `encoding/json` import**

`handleSimplePackage` (Task 2) marshals the scoped-miss audit metadata with `json.Marshal`. Add `"encoding/json"` to the `internal/adapter/pypi/pypi.go` import block now (it is not currently imported), so Task 2 compiles.

- [ ] **Step 3: Change the struct + constructor**

In `internal/adapter/pypi/pypi.go`, add a resolver field and accept an `UpstreamSet`. Replace the struct's `upstreamURL string` usage by keeping it (for the default index) **and** adding the resolver:

```go
type PyPIAdapter struct {
	db               *config.GateDB
	cache            cache.CacheStore
	scanEngine       *scanner.Engine
	policyEngine     *policy.Engine
	upstreamURL      string // default index base (back-compat; == resolver default)
	filesHost        string // default index file CDN; defaults to pypiFilesHost
	resolver         *adapter.UpstreamResolver
	router           http.Handler
	httpClient       *http.Client
	tagMutabilityCfg config.TagMutabilityConfig
}

func NewPyPIAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreams config.UpstreamSet,
	tagMutabilityCfg config.TagMutabilityConfig,
) *PyPIAdapter {
	defaultURL := upstreams.DefaultOr("https://pypi.org")
	resolver, err := adapter.NewUpstreamResolver("pypi", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		// Validation happened at config load; a build error here is a programming bug.
		panic(fmt.Sprintf("pypi: building upstream resolver: %v", err))
	}
	a := &PyPIAdapter{
		db:               db,
		cache:            cacheStore,
		scanEngine:       scanEngine,
		policyEngine:     policyEngine,
		upstreamURL:      strings.TrimRight(defaultURL, "/"),
		filesHost:        pypiFilesHost,
		resolver:         resolver,
		httpClient:       adapter.NewProxyHTTPClient(5 * time.Minute),
		tagMutabilityCfg: tagMutabilityCfg,
	}
	a.router = a.buildRouter()
	return a
}
```

- [ ] **Step 4: Update `main.go`**

In `cmd/shieldoo-gate/main.go`, change the PyPI wiring (line ~503). Remove the now-unused `pypiUpstream` string for PyPI and pass the set:

```go
	pypiAdapter := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.PyPI, tagMutCfg)
```

(Leave the other ecosystems on their `*Upstream` strings — they migrate in Phases 4–6. If `pypiUpstream` is now unused, delete its declaration from the block added in Phase 1.)

- [ ] **Step 5: Run the full PyPI unit suite + build**

Run: `go test ./internal/adapter/pypi/ -v && go build ./...`
Expected: all existing PyPI tests PASS (default-only path unchanged), build clean.

- [ ] **Step 6: Commit**

```bash
git add internal/adapter/pypi/pypi.go internal/adapter/pypi/pypi_test.go cmd/shieldoo-gate/main.go
git commit -m "feat(pypi): wire UpstreamResolver (default-only behaviour unchanged)"
```

---

## Task 2: `ScopeMatches` + per-index `/simple/{package}/` fan-out with rewrite

**Files:**
- Modify: `internal/adapter/upstream_set.go` (+ `ScopeMatches`, `ClaimingIndexNames`, `RewriteExtraIndexSimplePage`)
- Modify: `internal/adapter/upstream_set_test.go`
- Modify: `internal/adapter/pypi/pypi.go` (`handleSimplePackage`)
- Test: `internal/adapter/pypi/pypi_test.go`

- [ ] **Step 1: Write the failing resolver tests**

Add to `internal/adapter/upstream_set_test.go`:

```go
func TestScopeMatches_ClaimedNamespace_True(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://corp.example.com/", Packages: []string{"mycompany-*"}},
		},
	})
	assert.True(t, r.ScopeMatches("mycompany-secret"))
	assert.False(t, r.ScopeMatches("requests"))
}
```

- [ ] **Step 2: Implement `ScopeMatches` + `ClaimingIndexNames`**

Add to `internal/adapter/upstream_set.go`:

```go
// ScopeMatches reports whether the package name is claimed by any scoped index.
// When true and no index serves the package, the request is a scoped miss
// (404, no fallback) rather than a normal not-found.
func (r *UpstreamResolver) ScopeMatches(name string) bool {
	return len(r.ClaimingIndexNames(name)) > 0
}

// ClaimingIndexNames returns the names of every scoped index whose globs claim
// the package name (in config order). Used for the scoped-miss audit so an admin
// can see which private index(es) should have served a now-404'd package.
func (r *UpstreamResolver) ClaimingIndexNames(name string) []string {
	canon := r.canonical(name)
	var out []string
	for _, e := range r.extras {
		if len(e.packages) > 0 && matchAny(e.packages, canon) {
			out = append(out, e.Name)
		}
	}
	return out
}
```

Run: `go test ./internal/adapter/ -run 'TestScopeMatches|TestClaimingIndexNames' -v` → PASS. (Add a `TestClaimingIndexNames_ReturnsMatchingNames` mirroring `TestScopeMatches`.)

- [ ] **Step 3: Implement the fail-closed EXTRA-index page rewrite (failing test first)**

> **Design correction (review finding #2):** the rewrite is **byte-level**, operating on the raw
> response and substituting only the matched `href` attribute values — NOT an `x/net/html`
> tokenize→reserialize (that round-trip unescapes+re-escapes and reorders attributes, perturbing
> `data-requires-python` / `data-dist-info-metadata` and breaking the byte-identical default-index
> guarantee). The **default index keeps the existing `pypiDownloadURLRe` regex unchanged**; this new
> helper is ONLY for extra indexes.

Add to `internal/adapter/upstream_set_test.go`:

```go
func TestRewriteExtraIndex_RewritesAbsoluteToExtPackages(t *testing.T) {
	in := `<a href="https://files.corp.example.com/whl/foo-1.0.whl#sha256=x">foo</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	assert.Contains(t, string(out), `href="/ext-packages/corp/whl/foo-1.0.whl#sha256=x"`)
}

func TestRewriteExtraIndex_RelativeURLResolvedAndRewritten(t *testing.T) {
	in := `<a href="../../whl/foo-1.0.whl">foo</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://files.corp.example.com/simple/foo/")
	require.NoError(t, err)
	assert.Contains(t, string(out), `href="/ext-packages/corp/whl/foo-1.0.whl"`)
}

func TestRewriteExtraIndex_IndexHostWhenNoFilesHost(t *testing.T) {
	in := `<a href="https://corp.example.com/packages/foo-1.0.tar.gz">foo</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp"}, // no files_host → index host serves files
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	assert.Contains(t, string(out), `href="/ext-packages/corp/packages/foo-1.0.tar.gz"`)
}

func TestRewriteExtraIndex_UnroutableAbsoluteURL_FailsClosed(t *testing.T) {
	// An absolute download URL whose host is neither the index nor its files host
	// cannot be routed through the proxy → must error (serving it = scan bypass).
	in := `<a href="https://evil.cdn.example.net/foo-1.0.whl">foo</a>`
	_, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	require.Error(t, err)
}

func TestRewriteExtraIndex_PreservesNonHrefBytes(t *testing.T) {
	// data-requires-python and other attributes/bytes must survive verbatim.
	in := `<a href="https://corp.example.com/packages/foo-1.0.whl" data-requires-python="&gt;=3.8" data-dist-info-metadata="sha256=abc">foo-1.0</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `data-requires-python="&gt;=3.8"`)  // unchanged
	assert.Contains(t, s, `data-dist-info-metadata="sha256=abc"`) // unchanged
	assert.Contains(t, s, `href="/ext-packages/corp/packages/foo-1.0.whl"`)
}
```

- [ ] **Step 4: Implement `RewriteExtraIndexSimplePage` (byte-level)**

Add to `internal/adapter/upstream_set.go` (import `bytes`, `regexp`; `net/url` already imported):

```go
// hrefAttrRe matches an anchor href attribute value (double- or single-quoted).
// Submatch groups: 1 = whole quoted token, 2 = double-quoted value, 3 = single-quoted value.
var hrefAttrRe = regexp.MustCompile(`(?i)href\s*=\s*("([^"]*)"|'([^']*)')`)

// RewriteExtraIndexSimplePage rewrites the download anchors of an EXTRA index's
// PEP 503 simple page so artifacts route through the proxy's /ext-packages/<name>/
// scan pipeline. It substitutes ONLY matched href values in the raw bytes; every
// other byte (doctype, comments, other attributes like data-requires-python) is
// preserved verbatim. The DEFAULT index is NOT handled here — it keeps the legacy
// pypiDownloadURLRe regex in the adapter.
//
// FAIL CLOSED: an absolute http(s) href whose host is neither the index host nor
// its configured files host returns an error — serving such a page would let pip
// fetch the artifact directly, bypassing scanning.
func RewriteExtraIndexSimplePage(body []byte, idx ResolvedIndex, pageURL string) ([]byte, error) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("upstream: parsing page URL %q: %w", pageURL, err)
	}
	allowed := map[string]bool{base.Host: true} // index host serves files when files_host unset
	if idx.FilesHost != "" {
		if fh, e := url.Parse(idx.FilesHost); e == nil {
			allowed[fh.Host] = true
		}
	}

	var out bytes.Buffer
	last := 0
	for _, m := range hrefAttrRe.FindAllSubmatchIndex(body, -1) {
		valStart, valEnd := m[4], m[5] // double-quoted value
		if valStart < 0 {
			valStart, valEnd = m[6], m[7] // single-quoted value
		}
		raw := string(body[valStart:valEnd])
		rewritten, err := rewriteExtraHref(raw, idx, base, allowed)
		if err != nil {
			return nil, err
		}
		out.Write(body[last:valStart])
		out.WriteString(rewritten)
		last = valEnd
	}
	out.Write(body[last:])
	return out.Bytes(), nil
}

func rewriteExtraHref(href string, idx ResolvedIndex, base *url.URL, allowed map[string]bool) (string, error) {
	ref, err := url.Parse(href)
	if err != nil {
		return href, nil // leave malformed hrefs untouched
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return href, nil // fragment-only, mailto:, data: — leave alone
	}
	if !allowed[abs.Host] {
		return "", fmt.Errorf("upstream: index %q simple page links to unroutable host %q (would bypass scanning)", idx.Name, abs.Host)
	}
	suffix := strings.TrimPrefix(abs.Path, "/")
	if abs.RawQuery != "" {
		suffix += "?" + abs.RawQuery
	}
	if abs.Fragment != "" {
		suffix += "#" + abs.Fragment
	}
	return "/ext-packages/" + idx.Name + "/" + suffix, nil
}
```

Run: `go test ./internal/adapter/ -run TestRewriteExtraIndex -v` → PASS (5 tests).

> **Note on HTML entities in hrefs:** PEP 503 file URLs carry the hash in a URL **fragment**
> (`#sha256=…`), not a query, so `&amp;`-style entity encoding does not occur in practice. If an
> upstream ever entity-encodes a query `&`, `url.Parse` of the raw attribute would mis-split it; this
> is an accepted limitation (documented in Phase 8 docs) and does not weaken the fail-closed host check.

- [ ] **Step 5: Rewrite `handleSimplePackage` to fan over indexes (failing test first)**

Add to `internal/adapter/pypi/pypi_test.go` a multi-index test (see Task 2 Step 7 for the full helper). Minimal first assertion:

```go
func TestPyPIAdapter_ScopedMiss_Returns404(t *testing.T) {
	// corp claims mycompany-*; corp returns 404 for it; no public fallback.
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{
		{Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/simple/mycompany-secret/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
```

```go
func TestPyPIAdapter_ScopedIndex500_Returns404NoPublicFallback(t *testing.T) {
	// Security guard: a claimed name whose index errors (500) must 404, never
	// fall through to the public default.
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{
		{Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/simple/mycompany-secret/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
```

Add the helper `newMultiIndexAdapter` near `setupTestPyPI`:

```go
func newMultiIndexAdapter(t *testing.T, defaultURL string, extras []config.UpstreamIndex) *pypi.PyPIAdapter {
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
	return pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: defaultURL, ExtraIndexes: extras}, config.TagMutabilityConfig{})
}
```

- [ ] **Step 6: Implement the fan-out in `handleSimplePackage`**

Replace `handleSimplePackage` (and `proxyUpstreamRewrite`'s single-upstream use) in `internal/adapter/pypi/pypi.go` with index-aware logic:

```go
func (a *PyPIAdapter) handleSimplePackage(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	if err := adapter.ValidatePackageName(pkg); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package name", Reason: err.Error()})
		return
	}

	indexes := a.resolver.ResolveForPackage(pkg)
	for _, idx := range indexes {
		served, err := a.tryServeSimple(w, r, idx, pkg)
		if err != nil {
			a.resolver.ObserveProbe(idx.Name, "error")
			continue // try next index
		}
		if served {
			a.resolver.ObserveProbe(idx.Name, "hit")
			return
		}
		a.resolver.ObserveProbe(idx.Name, "miss")
	}

	// Nothing served. A claimed-namespace miss is a hard 404 (no fallback) + audit.
	if claimants := a.resolver.ClaimingIndexNames(pkg); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		// Namespace the synthetic audit ID under the first claiming index so an
		// admin can tell which private index should have served it (finding #4).
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemPyPI), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, CanonicalName(pkg)),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index package not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	adapter.WriteJSONError(w, http.StatusNotFound, adapter.ErrorResponse{Error: "not found", Artifact: pkg, Reason: "package not found on any configured index"})
}

// tryServeSimple fetches the index's simple page for pkg. Returns (served=true)
// when the index has the package (200) and the page was rewritten + relayed.
// Returns (served=false, nil) on 404; (false, err) on transport/upstream error.
func (a *PyPIAdapter) tryServeSimple(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, pkg string) (bool, error) {
	pageURL, err := url.JoinPath(idx.URL, "/simple/"+pkg+"/")
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, pageURL, nil)
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
		return false, fmt.Errorf("pypi: index %q returned %d", idx.Name, resp.StatusCode)
	}

	const maxMetadataSize = 200 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("pypi: index %q metadata exceeds size limit", idx.Name)
	}

	var rewritten []byte
	if idx.Name == "" {
		// DEFAULT index: legacy byte-identical regex rewrite (files.pythonhosted.org → /packages/).
		rewritten = pypiDownloadURLRe.ReplaceAll(body, []byte("/packages/"))
	} else {
		// EXTRA index: byte-level href substitution, fail-closed on unroutable hosts.
		var rerr error
		rewritten, rerr = adapter.RewriteExtraIndexSimplePage(body, idx, pageURL)
		if rerr != nil {
			// Fail closed: a page we cannot fully route would let pip bypass the gate.
			log.Error().Err(rerr).Str("index", idx.Name).Str("package", pkg).Msg("SECURITY: simple-page rewrite failed, refusing to serve")
			http.Error(w, "upstream metadata could not be safely rewritten", http.StatusBadGateway)
			return true, nil // response written; do not try other indexes
		}
	}

	for key, vals := range resp.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rewritten)
	return true, nil
}
```

> `handleSimpleIndex` (root `/simple/`) stays as-is — it serves only the default index (documented limitation; pip queries per-package). `proxyUpstreamRewrite` is now unused for the per-package path (the default `/packages/` rewrite is done inline in `tryServeSimple` via `pypiDownloadURLRe`); if no caller remains, delete it. Keep `pypiDownloadURLRe` — it is still used by `tryServeSimple`.

- [ ] **Step 7: Add a positive multi-index serve test**

Add to `internal/adapter/pypi/pypi_test.go`:

```go
func TestPyPIAdapter_ExtraIndexServesSimplePage_RewritesToExtPackages(t *testing.T) {
	hexaly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/hexaly/" {
			w.Header().Set("Content-Type", "text/html")
			// absolute URL on the index host (no separate files_host)
			_, _ = w.Write([]byte(`<a href="` + "http://" + r.Host + `/packages/hexaly-1.0.tar.gz">hexaly-1.0.tar.gz</a>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(hexaly.Close)

	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{
		{Name: "hexaly", URL: hexaly.URL}, // unscoped fallback index
	})
	req := httptest.NewRequest(http.MethodGet, "/simple/hexaly/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `/ext-packages/hexaly/packages/hexaly-1.0.tar.gz`)
}
```

- [ ] **Step 8: Run + commit**

Run: `go test ./internal/adapter/... -run 'PyPI|ScopeMatches|RewriteExtraIndex' -v && go build ./...`
Expected: PASS; build clean.

```bash
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go internal/adapter/pypi/pypi.go internal/adapter/pypi/pypi_test.go
git commit -m "feat(pypi): multi-index /simple fan-out + fail-closed per-index rewrite + scoped-miss audit"
```

---

---

## Security hardening (post-review)

Applied to Task 2 implementation during security review (2026-06-19). All changes are FAIL-CLOSED and affect EXTRA indexes only (default index behaviour is byte-identical).

**FIX A — PEP 691 JSON / non-HTML response = scan bypass (CRITICAL)**
`tryServeSimple` no longer relays the client's `Accept` header to extra indexes. Instead it forces `text/html, application/vnd.pypi.simple.v1+html;q=0.9` so the upstream cannot return JSON. After a 200 response, the Content-Type is validated: if it does not contain `text/html` or `application/vnd.pypi.simple.v1+html` (including a missing Content-Type — handled at the HTTP level by Go's content sniffing, tested via explicit non-HTML types), the handler fails closed: logs `SECURITY: extra index returned non-HTML simple page`, returns HTTP 502, and does not try further indexes. **Documented limitation:** PEP 691 JSON is not yet supported for extra indexes; a future phase can add a JSON parser that fails closed on any un-rewritable URL.

**FIX B — Unquoted hrefs evade regex; `data-href` over-match (HIGH + LOW)**
`hrefAttrRe` replaced with a new regex that (1) requires a left-boundary character so `data-href=` does not match, and (2) matches unquoted href values (valid HTML). The substitution loop now strips quotes before rewriting and always emits double-quoted output, so an unquoted source href becomes a double-quoted proxy href.

**FIX C — Path traversal in rewritten suffix (MEDIUM)**
`rewriteExtraHref` rejects any resolved path containing a literal `..` segment (after Go's URL normalisation). Note: Go's `url.Parse` + `ResolveReference` normalise most `..` forms away at parse time, so this guard targets non-standard servers that return raw `..` bytes that survive into `abs.Path`.

**FIX D — Case-insensitive host comparison (LOW)**
`RewriteExtraIndexSimplePage` lower-cases hosts when building the allowed set; `rewriteExtraHref` compares `strings.ToLower(abs.Host)`.

**FIX E — Restrict relayed headers for extra indexes (MEDIUM)**
The header-relay loop in `tryServeSimple` now uses an allowlist (`Content-Type`, `ETag`, `Last-Modified`) for extra indexes to prevent a low-trust upstream from injecting `Set-Cookie`, `CSP`, `Link`, etc.

---

## Task 3: SSRF-safe `/ext-packages/{index}/*` download route with per-index auth

**Files:**
- Modify: `internal/adapter/pypi/pypi.go` (router ~99-105; download pipeline)
- Test: `internal/adapter/pypi/pypi_test.go`

> **Defence-in-depth note:** The `/ext-packages/{index}/*` route handler MUST also reject `..` path segments in the incoming request path before constructing the upstream URL — this provides a second layer of path-traversal protection independent of the `rewriteExtraHref` check applied at simple-page rewrite time.

- [ ] **Step 1: Write failing tests**

Add to `internal/adapter/pypi/pypi_test.go`:

```go
func TestPyPIAdapter_ExtPackagesUnknownIndex_Returns404NoUpstream(t *testing.T) {
	// Forged/unknown index name must 404 before any upstream request (SSRF control).
	a := newMultiIndexAdapter(t, "https://pypi.invalid", nil)
	req := httptest.NewRequest(http.MethodGet, "/ext-packages/ghost/foo-1.0.tar.gz", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPyPIAdapter_ExtPackagesDownload_ScansAndNamespacesArtifact(t *testing.T) {
	var sentAuth string
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentAuth = r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/mycompany-lib-1.0.tar.gz") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("dummy-sdist-bytes"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_CORP_TOK", "tok-123")

	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_CORP_TOK"},
	}})
	// files served from the index host (no files_host) → path after host is "mycompany-lib-1.0.tar.gz"
	req := httptest.NewRequest(http.MethodGet, "/ext-packages/corp/mycompany-lib-1.0.tar.gz", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	// No scanners registered → clean → served 200.
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Bearer tok-123", sentAuth, "upstream auth header attached")

	// Artifact cached under the namespaced ecosystem segment "pypi__corp".
	status, err := adapter.GetArtifactStatus(a.DB(), "pypi__corp:mycompany-lib:1.0:mycompany-lib-1.0.tar.gz")
	require.NoError(t, err)
	require.NotNil(t, status)
}
```

> `a.DB()` accessor: if PyPIAdapter has no public DB getter, add one (`func (a *PyPIAdapter) DB() *config.GateDB { return a.db }`) gated `// test-only accessor`, or assert via the cache `Get`. Prefer the cache check if a DB getter is undesirable: `_, err := <cacheStore>.Get(...)`. Choose one and keep the test self-contained.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/adapter/pypi/ -run TestPyPIAdapter_ExtPackages -v`
Expected: FAIL — route `/ext-packages/...` not registered (404 from chi for the second test too, or panic on `DB()`).

- [ ] **Step 3: Register the route + thread an `indexContext` through the pipeline**

In `internal/adapter/pypi/pypi.go` `buildRouter`, add:

```go
	r.Get("/ext-packages/{index}/*", a.handleExtraPackageDownload)
```

Add an `indexContext` and the new handler; refactor `handlePackageDownload` to delegate to a shared core:

```go
// indexContext carries the serving index's identity through the download pipeline.
type indexContext struct {
	name      string // "" for the default index
	filesBase string // absolute base to prepend before the relative file path
	auth      string // Authorization header value, or ""
}

func (a *PyPIAdapter) ecosystemSeg(ic indexContext) string {
	return adapter.NamespacedEcosystem(string(scanner.EcosystemPyPI), ic.name)
}

// handlePackageDownload — DEFAULT index (unchanged contract: /packages/*).
func (a *PyPIAdapter) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	filePath := chi.URLParam(r, "*")
	ic := indexContext{name: "", filesBase: a.filesHost + "/packages/", auth: ""}
	upstreamFull := ic.filesBase + filePath
	if strings.HasSuffix(filePath, ".metadata") {
		a.proxyDirectAuthed(w, r, upstreamFull, ic.auth)
		return
	}
	a.downloadScanServe(w, r, upstreamFull, filePath, ic)
}

// handleExtraPackageDownload — EXTRA indexes (/ext-packages/{index}/*).
func (a *PyPIAdapter) handleExtraPackageDownload(w http.ResponseWriter, r *http.Request) {
	index := chi.URLParam(r, "index")
	// SSRF control: validate the index name and resolve its files host BEFORE
	// building any upstream URL. Unknown/forged → 404, no upstream request.
	if !upstreamIndexNameOK(index) {
		http.NotFound(w, r)
		return
	}
	idx, ok := a.resolver.IndexByName(index)
	if !ok {
		http.NotFound(w, r)
		return
	}
	filesBase := idx.FilesHost
	if filesBase == "" {
		filesBase = idx.URL // files served from the index host when files_host unset
	}
	filePath := chi.URLParam(r, "*")
	upstreamFull := strings.TrimRight(filesBase, "/") + "/" + filePath
	ic := indexContext{name: index, filesBase: strings.TrimRight(filesBase, "/") + "/", auth: a.resolver.AuthHeader(idx)}
	if strings.HasSuffix(filePath, ".metadata") {
		a.proxyDirectAuthed(w, r, upstreamFull, ic.auth)
		return
	}
	a.downloadScanServe(w, r, upstreamFull, filePath, ic)
}

// upstreamIndexNameOK mirrors config's index-name rule (^[a-z0-9-]+$).
var extIndexNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

func upstreamIndexNameOK(s string) bool { return extIndexNameRe.MatchString(s) }
```

- [ ] **Step 4: Thread `indexContext` into `downloadScanServe` artifact IDs**

In `downloadScanServe`, change the signature to accept `ic indexContext` and replace the artifact-ID construction (line ~186) so the eco segment is namespaced:

```go
func (a *PyPIAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, upstreamURL, filePath string, ic indexContext) {
	// ... unchanged parse of filename / pkgName / pkgVersion ...
	artifactID := pypiArtifactIDForEco(a.ecosystemSeg(ic), pkgName, pkgVersion, filename)
	// ... rest of the pipeline unchanged, EXCEPT the download request must carry ic.auth ...
}
```

Add the eco-aware ID builder next to `PyPIArtifactID`:

```go
// pypiArtifactIDForEco builds a 4-segment artifact ID with an explicit eco
// segment (e.g. "pypi" or "pypi__corp"). PyPIArtifactID is the default-eco shorthand.
func pypiArtifactIDForEco(eco, name, version, filename string) string {
	return fmt.Sprintf("%s:%s:%s:%s", eco, name, version, filename)
}
```

Find the download call inside `downloadScanServe` (`downloadToTemp(ctx, upstreamURL, a.httpClient)`) and add auth:

```go
	tmpPath, size, sha, err := downloadToTempAuthed(ctx, upstreamURL, ic.auth, a.httpClient)
```

Add an auth-aware download + a `proxyDirectAuthed`:

```go
func downloadToTempAuthed(ctx context.Context, rawURL, authHeader string, client *http.Client) (string, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", fmt.Errorf("pypi: download: building request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("pypi: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("pypi: download: upstream returned %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "shieldoo-gate-pypi-*.tmp")
	if err != nil {
		return "", 0, "", fmt.Errorf("pypi: download: creating temp file: %w", err)
	}
	defer tmp.Close()
	h := sha256.New()
	mw := io.MultiWriter(tmp, h)
	const maxArtifactSize int64 = 2 << 30
	size, err := io.Copy(mw, io.LimitReader(resp.Body, maxArtifactSize))
	if err != nil {
		os.Remove(tmp.Name())
		return "", 0, "", fmt.Errorf("pypi: download: writing temp file: %w", err)
	}
	return tmp.Name(), size, hex.EncodeToString(h.Sum(nil)), nil
}

// proxyDirectAuthed relays a PEP 658 .metadata file. These are unscanned, so the
// relay is hardened: a 10 MB size cap and an allowlist of safe response headers
// (NEVER relay Set-Cookie or arbitrary headers from a less-trusted private index).
func (a *PyPIAdapter) proxyDirectAuthed(w http.ResponseWriter, r *http.Request, target, authHeader string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	const maxMetadataFileSize = 10 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataFileSize+1))
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	if int64(len(body)) > maxMetadataFileSize {
		http.Error(w, "upstream .metadata exceeds size limit", http.StatusBadGateway)
		return
	}
	// Allowlist of safe headers only.
	for _, h := range []string{"Content-Type", "ETag", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}
```

> Replace the old `downloadToTemp`/`proxyDirect` call sites with the `*Authed` variants (the default path passes `auth=""`, preserving behaviour). Keep the originals only if other callers remain; otherwise remove to avoid dead code (CLAUDE.md cleanup discipline).

- [ ] **Step 5: Add the DB test accessor (if used) and run**

If the Task 3 test uses `a.DB()`, add to `pypi.go`:

```go
// DB exposes the adapter's database handle for tests.
func (a *PyPIAdapter) DB() *config.GateDB { return a.db }
```

Run: `go test ./internal/adapter/pypi/ -v && go build ./...`
Expected: PASS, build clean. Verify the default-index tests (`/packages/...`) still pass unchanged.

- [ ] **Step 6: Commit**

```bash
git add internal/adapter/pypi/pypi.go internal/adapter/pypi/pypi_test.go
git commit -m "feat(pypi): /ext-packages/{index} download route (SSRF-safe, auth, namespaced IDs)"
```

---

## Task 4: Light docs + config.example.yaml (full docs/ADR in Phase 8; E2E in Phase 4)

> The full `docs/` adapter page and ADR-017 are written in **Phase 8**; the shell **E2E + example
> project** are **Phase 4** (the dedicated E2E phase). This task adds only the minimal
> `config.example.yaml` schema block so the new config shape is discoverable, satisfying CLAUDE.md's
> "docs updated alongside code" rule for the config surface introduced here.

**Files:**
- Modify: `config.example.yaml`

- [ ] **Step 1: Document the schema in `config.example.yaml`**

Add a commented PyPI multi-index block showing `default` + `extra_indexes` (Hexaly-style unscoped + a scoped private index with `packages`, `files_host`, env-var `auth`). Keep the bare-string form (`pypi: "https://pypi.org"`) documented as the back-compat default. Example:

```yaml
upstreams:
  # Back-compat: a bare string still works and behaves exactly as before.
  # pypi: "https://pypi.org"
  pypi:
    default: "https://pypi.org"
    extra_indexes:
      - name: "hexaly"                       # unscoped fallback (public vendor index)
        url: "https://pip.hexaly.com/hexaly/"
      - name: "corp"                         # private index, pinned to a namespace
        url: "https://pkgs.internal.example.com/simple/"
        packages: ["mycompany-*", "acme-*"]
        files_host: "https://files.internal.example.com/"
        auth:
          type: "basic"                      # "bearer" | "basic"
          token_env: "SGW_CORP_INDEX_TOKEN"  # env var only — never plaintext
```

- [ ] **Step 2: Full phase verification**

Run: `make build && make lint && make test`
Expected: all green (unit + httptest integration). The shell E2E is exercised in **Phase 4**.

- [ ] **Step 3: Commit**

```bash
git add config.example.yaml
git commit -m "docs(pypi): document multi-index config schema in config.example.yaml"
```

---

## Phase 3 done-when

- [ ] Default-only PyPI config behaves byte-identically to pre-feature (all legacy tests green; default rewrite still via `pypiDownloadURLRe`).
- [ ] `/simple/{package}/` resolves across indexes (ordered fallback + scoping); first hit serves.
- [ ] Extra-index file URLs rewrite via byte-level substitution; an extra index that links to an unroutable host **fails closed** (502), never bypasses scanning; non-href bytes preserved.
- [ ] `/ext-packages/{index}/*` downloads are SSRF-safe (unknown index → 404 pre-upstream), carry per-index env-var auth, and store artifacts under the `pypi__<index>` ecosystem segment.
- [ ] Scoped-namespace miss (incl. all claiming indexes breaker-open, or a claiming index 500ing) → 404 (no fallback) + namespaced audit row + `upstream_scoped_miss_total` metric.
- [ ] `.metadata` relay is size-capped + safe-header-allowlisted.
- [ ] `config.example.yaml` updated; example project + shell E2E land in Phase 4; full docs/ADR-017 in Phase 8.
- [ ] `make build && make lint && make test` all green (in-process tests). End-to-end `pip` validation is Phase 4.
