# Multi-Upstream Indexes — Phase 5: npm + NuGet

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run E2E redirected to a log file, then tail it (per the repo's E2E-via-logfile convention).

**Goal:** Extend the proven Phase 2 resolver + Phase 3 PyPI reference pattern to the **npm** and **NuGet** adapters: fan metadata requests across the default + extra indexes (ordered fallback + glob scoping), rewrite each serving index's download URLs through the proxy scan pipeline **fail-closed**, recover the serving index on the download leg by **re-resolving the package name** (the npm/nuget download routes already carry the package id — no `/ext-packages/` route needed, unlike PyPI), namespace artifact IDs via `eco__<index>`, and audit scoped-misses. Extend the Phase 4 docker-compose E2E harness with private npm + NuGet feeds and prove the non-negotiable release gate: **a secondary-index artifact is scanned + cached, not bypassed.**

**Architecture:** Default-index behaviour stays byte-identical (npm packument tarball rewrite via the existing serving-origin string replace; NuGet service-index/registration rewrite unchanged). Extra indexes use a **JSON-aware, key-targeted, fail-closed** rewrite: npm rewrites only `versions.*.dist.tarball` (fail closed if a tarball host is not the serving/files host); NuGet rewrites the serving-index origin then **parses the result and fails closed (502) if any `packageContent` or registration `@id` URL still points at a foreign host** (a download-URL rewrite miss is a silent full scan bypass). The download handlers re-run `ResolveForPackage(pkg)` to recover `{index, url, auth}` deterministically, then namespace the artifact ID with `adapter.NamespacedEcosystem`. A claimed-namespace miss returns 404 (no public fallback) and is audited under `eco__<firstClaimant>` — exactly as PyPI.

**Tech Stack:** Go 1.25, `github.com/go-chi/chi/v5`, `encoding/json` (npm/nuget metadata is JSON — a real parser, not a byte regex, satisfies the "use a real parser for adversarial markup" mandate), the Phase 2 `adapter.UpstreamResolver`, `net/http/httptest` (unit/integration), docker-compose + Caddy + the real `npm`/`dotnet` clients (E2E).

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

---

## Security mandate (carried from the plan index — non-negotiable for this phase)

Every per-ecosystem metadata rewrite is a scan-bypass surface. npm + NuGet MUST:

- **(a)** fail closed on any **download URL** (npm `dist.tarball`, NuGet `packageContent`) whose host is not the serving index host or its configured files host;
- **(b)** fail closed on a non-JSON / unparseable extra-index metadata response it cannot safely rewrite (never relay verbatim);
- **(c)** use a **real JSON parser** (`encoding/json`), not a string-replace-only pass, for the extra-index fail-closed host check;
- **(d)** get a dedicated **security review of the implementation** (security-code-review skill), not just this plan.

The default index keeps its current byte-identical rewrite (string replace of the serving origin) — that path is unchanged and out of scope for the fail-closed parser.

---

## File structure

- **Modify:** `internal/adapter/upstream_set.go` — add `RewriteNPMPackumentTarballs` (npm) and `AssertNoForeignNuGetDownloadURLs` (nuget) shared helpers + unit tests.
- **Modify:** `internal/adapter/upstream_set_test.go` — helper unit tests.
- **Modify:** `internal/adapter/npm/npm.go` — constructor takes `config.UpstreamSet`; resolver field; metadata fan-out; download index recovery + namespaced IDs + auth; scoped-miss audit.
- **Modify:** `internal/adapter/npm/npm_test.go` — migrate setup to new constructor; add multi-index unit tests.
- **Modify:** `internal/adapter/nuget/nuget.go` — same shape as npm for the NuGet V3 surface.
- **Modify:** `internal/adapter/nuget/nuget_test.go` — same.
- **Modify:** `cmd/shieldoo-gate/main.go` — pass `cfg.Upstreams.NPM` / `cfg.Upstreams.NuGet` (UpstreamSet) to the constructors; drop the now-unused `npmUpstream` / `nugetUpstream` strings.
- **Modify:** `config.example.yaml` — npm + nuget multi-index schema blocks.
- **Create:** `examples/npm-private-registry/`, `examples/nuget-private-feed/`.
- **Modify (config migration):** `docker/config.yaml`, `examples/deploy/config.yaml`, `.deploy/config.yaml` (if present), Helm `values.yaml` + `configmap.yaml` — restructure `npm`/`nuget` to the `default:` form (shape-only; no prod `extra_indexes`).
- **Create:** `tests/e2e-shell/fixtures/private-npm/`, `tests/e2e-shell/fixtures/private-nuget/`, `tests/e2e-shell/test_npm_multi_index.sh`, `tests/e2e-shell/test_nuget_multi_index.sh`.
- **Modify:** `tests/e2e-shell/config.e2e.yaml` (wire npm/nuget multi-index), `tests/e2e-shell/docker-compose.e2e.yml` (serve the private feeds — reuse the existing `private-index` Caddy server + CA), `tests/e2e-shell/run_all.sh` (register the two new tests).
- **Modify:** `docs/` — npm + nuget adapter pages (multi-index section) + `docs/index.md` link if needed.

Depends on Phase 1 (`config.UpstreamSet`), Phase 2 (`adapter.UpstreamResolver`), Phase 3 (reference pattern), Phase 4 (E2E harness).

---

## Task 1: Shared fail-closed JSON rewrite helpers

**Files:**
- Modify: `internal/adapter/upstream_set.go`
- Test: `internal/adapter/upstream_set_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/adapter/upstream_set_test.go`:

```go
func TestRewriteNPMPackumentTarballs_RewritesServingHost(t *testing.T) {
	in := []byte(`{"versions":{"1.0.0":{"dist":{"tarball":"https://npm.corp.example.com/foo/-/foo-1.0.0.tgz","shasum":"abc"}}},"repository":{"url":"git+https://github.com/x/foo.git"}}`)
	out, err := RewriteNPMPackumentTarballs(in,
		ResolvedIndex{Name: "corp", URL: "https://npm.corp.example.com"},
		"http://gate.local")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `"tarball":"http://gate.local/foo/-/foo-1.0.0.tgz"`)
	assert.Contains(t, s, `"shasum":"abc"`)                       // integrity preserved
	assert.Contains(t, s, `git+https://github.com/x/foo.git`)    // non-download URL untouched
}

func TestRewriteNPMPackumentTarballs_ForeignTarballHost_FailsClosed(t *testing.T) {
	in := []byte(`{"versions":{"1.0.0":{"dist":{"tarball":"https://evil.cdn.example.net/foo-1.0.0.tgz"}}}}`)
	_, err := RewriteNPMPackumentTarballs(in,
		ResolvedIndex{Name: "corp", URL: "https://npm.corp.example.com"}, "http://gate.local")
	require.Error(t, err)
}

func TestRewriteNPMPackumentTarballs_FilesHostAllowed(t *testing.T) {
	in := []byte(`{"versions":{"1.0.0":{"dist":{"tarball":"https://files.corp.example.com/foo-1.0.0.tgz"}}}}`)
	out, err := RewriteNPMPackumentTarballs(in,
		ResolvedIndex{Name: "corp", URL: "https://npm.corp.example.com", FilesHost: "https://files.corp.example.com"},
		"http://gate.local")
	require.NoError(t, err)
	assert.Contains(t, string(out), `"tarball":"http://gate.local/foo-1.0.0.tgz"`)
}

func TestRewriteNPMPackumentTarballs_InvalidJSON_FailsClosed(t *testing.T) {
	_, err := RewriteNPMPackumentTarballs([]byte(`not json`),
		ResolvedIndex{Name: "corp", URL: "https://npm.corp.example.com"}, "http://gate.local")
	require.Error(t, err)
}

func TestAssertNoForeignNuGetDownloadURLs_ProxyOnly_OK(t *testing.T) {
	body := []byte(`{"items":[{"@id":"http://gate.local/v3/registration/foo/index.json#page",
		"items":[{"catalogEntry":{"packageContent":"http://gate.local/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg",
		"licenseUrl":"https://licenses.example.org/MIT"}}]}]}`)
	require.NoError(t, AssertNoForeignNuGetDownloadURLs(body, "gate.local"))
}

func TestAssertNoForeignNuGetDownloadURLs_ForeignPackageContent_FailsClosed(t *testing.T) {
	body := []byte(`{"items":[{"catalogEntry":{"packageContent":"https://evil.cdn/foo.nupkg"}}]}`)
	require.Error(t, AssertNoForeignNuGetDownloadURLs(body, "gate.local"))
}

func TestAssertNoForeignNuGetDownloadURLs_ForeignSubpage_FailsClosed(t *testing.T) {
	body := []byte(`{"items":[{"@id":"https://evil.feed/v3/registration/foo/page1.json"}]}`)
	require.Error(t, AssertNoForeignNuGetDownloadURLs(body, "gate.local"))
}
```

Run: `go test ./internal/adapter/ -run 'RewriteNPM|AssertNoForeignNuGet' -v` → FAIL (undefined helpers).

- [ ] **Step 2: Implement the helpers**

Add to `internal/adapter/upstream_set.go` (`encoding/json` is NOT yet imported here — add it to the import block):

```go
// RewriteNPMPackumentTarballs rewrites every versions.*.dist.tarball URL of an
// EXTRA-index npm packument so artifacts route through the proxy's scan pipeline.
// It is JSON-aware (parses the document) so it can FAIL CLOSED on any tarball
// whose host is neither the serving index host nor its configured files host —
// serving such a packument would let npm fetch the artifact directly, bypassing
// the scan. Non-download URLs (repository.url, homepage, …) are left untouched.
// The DEFAULT index is NOT handled here (it keeps the serving-origin string
// replace in the adapter, byte-identical to today).
//
// proxyOrigin is "<scheme>://<host>" (no trailing slash). The download leg
// recovers the serving index by re-resolving the package name, so the rewritten
// path is the tarball URL's path verbatim under the proxy origin.
func RewriteNPMPackumentTarballs(body []byte, idx ResolvedIndex, proxyOrigin string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		// FAIL CLOSED: a packument we cannot parse cannot be safely rewritten.
		return nil, fmt.Errorf("upstream: index %q packument is not valid JSON (cannot rewrite, refusing to serve): %w", idx.Name, err)
	}
	allowed := downloadHostSet(idx)
	versions, _ := doc["versions"].(map[string]any)
	for _, v := range versions {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		dist, ok := vm["dist"].(map[string]any)
		if !ok {
			continue
		}
		tb, ok := dist["tarball"].(string)
		if !ok || tb == "" {
			continue
		}
		rewritten, err := proxyRewriteDownloadURL(tb, idx.Name, allowed, proxyOrigin)
		if err != nil {
			return nil, err
		}
		dist["tarball"] = rewritten
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("upstream: index %q packument re-marshal: %w", idx.Name, err)
	}
	return out, nil
}

// AssertNoForeignNuGetDownloadURLs parses a NuGet V3 registration document that
// has ALREADY had its serving-index origin string-replaced to the proxy origin,
// and FAILS CLOSED if any download URL (packageContent) or registration sub-page
// link (@id) still points at a host other than proxyHost. After the string
// replace every serving-host URL is a proxy-host URL, so a surviving foreign host
// means either a foreign CDN download (scan bypass) or a foreign pagination page
// the gate would never see (transitive bypass). Non-download metadata URLs
// (licenseUrl, projectUrl) are ignored — they are not artifact or pagination links.
func AssertNoForeignNuGetDownloadURLs(body []byte, proxyHost string) error {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("nuget registration is not valid JSON (cannot verify, refusing to serve): %w", err)
	}
	proxyHost = strings.ToLower(proxyHost)
	var walkErr error
	var walk func(node any)
	walk = func(node any) {
		if walkErr != nil {
			return
		}
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				if s, ok := v.(string); ok && (k == "packageContent" || k == "@id") {
					if u, err := url.Parse(s); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
						if strings.ToLower(u.Host) != proxyHost {
							walkErr = fmt.Errorf("nuget registration links to unroutable host %q in %q (would bypass scanning)", u.Host, k)
							return
						}
					}
				}
				walk(v)
			}
		case []any:
			for _, v := range n {
				walk(v)
			}
		}
	}
	walk(doc)
	return walkErr
}

// downloadHostSet returns the lower-cased set of hosts an extra index may serve
// download URLs from: its own host and (optionally) its configured files host.
func downloadHostSet(idx ResolvedIndex) map[string]bool {
	allowed := map[string]bool{}
	if u, err := url.Parse(idx.URL); err == nil && u.Host != "" {
		allowed[strings.ToLower(u.Host)] = true
	}
	if idx.FilesHost != "" {
		if u, err := url.Parse(idx.FilesHost); err == nil && u.Host != "" {
			allowed[strings.ToLower(u.Host)] = true
		}
	}
	return allowed
}

// proxyRewriteDownloadURL rewrites an absolute download URL to proxyOrigin+path,
// failing closed if its host is not in allowed. Relative URLs are not expected in
// npm/nuget download fields; a non-absolute or non-http(s) value fails closed too.
func proxyRewriteDownloadURL(raw, idxName string, allowed map[string]bool, proxyOrigin string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("upstream: index %q download URL %q is not an absolute http(s) URL (cannot route, refusing to serve)", idxName, raw)
	}
	if !allowed[strings.ToLower(u.Host)] {
		return "", fmt.Errorf("upstream: index %q download URL host %q is unroutable (would bypass scanning)", idxName, u.Host)
	}
	suffix := u.Path
	if u.RawQuery != "" {
		suffix += "?" + u.RawQuery
	}
	return strings.TrimRight(proxyOrigin, "/") + suffix, nil
}
```

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/ -run 'RewriteNPM|AssertNoForeignNuGet|downloadHostSet' -v && go build ./...
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go
git commit -m "feat(upstream): fail-closed JSON download-URL rewrite helpers (npm/nuget)"
```

---

## Task 2: npm — resolver wiring (default-only behaviour unchanged)

**Files:**
- Modify: `internal/adapter/npm/npm.go` (struct ~31-40, constructor ~43-62)
- Modify: `cmd/shieldoo-gate/main.go` (~499, ~507)
- Test: `internal/adapter/npm/npm_test.go` (setup helper)

- [ ] **Step 1: Migrate the test setup helper to the new constructor (failing)**

In `internal/adapter/npm/npm_test.go`, change the `NewNPMAdapter` call in the setup helper (grep `NewNPMAdapter` in the test) to pass an `UpstreamSet`:

```go
a := npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine,
	config.UpstreamSet{Default: upstream.URL}, config.TagMutabilityConfig{})
```

Run: `go test ./internal/adapter/npm/ -run TestNPMAdapter -count=1` → FAIL to compile (constructor still wants a string).

- [ ] **Step 2: Change the struct + constructor**

In `internal/adapter/npm/npm.go`, add `resolver` and accept an `UpstreamSet`:

```go
type NPMAdapter struct {
	db               *config.GateDB
	cache            cache.CacheStore
	scanEngine       *scanner.Engine
	policyEngine     *policy.Engine
	upstreamURL      string // default index base (back-compat; == resolver default)
	resolver         *adapter.UpstreamResolver
	router           http.Handler
	httpClient       *http.Client
	tagMutabilityCfg config.TagMutabilityConfig
}

func NewNPMAdapter(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	upstreams config.UpstreamSet,
	tagMutabilityCfg config.TagMutabilityConfig,
) *NPMAdapter {
	defaultURL := upstreams.DefaultOr("https://registry.npmjs.org")
	resolver, err := adapter.NewUpstreamResolver("npm", config.UpstreamSet{
		Default:      defaultURL,
		ExtraIndexes: upstreams.ExtraIndexes,
	})
	if err != nil {
		panic(fmt.Sprintf("npm: building upstream resolver: %v", err))
	}
	a := &NPMAdapter{
		db:               db,
		cache:            cacheStore,
		scanEngine:       scanEngine,
		policyEngine:     policyEngine,
		upstreamURL:      strings.TrimRight(defaultURL, "/"),
		resolver:         resolver,
		httpClient:       adapter.NewProxyHTTPClient(5 * time.Minute),
		tagMutabilityCfg: tagMutabilityCfg,
	}
	a.router = a.buildRouter()
	return a
}
```

- [ ] **Step 3: Update `main.go`**

In `cmd/shieldoo-gate/main.go`, drop the `npmUpstream := …DefaultOr(…)` line and change the wiring:

```go
npmAdapter := npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.NPM, tagMutCfg)
```

- [ ] **Step 4: Run + commit**

```bash
go test ./internal/adapter/npm/ -v && go build ./...
git add internal/adapter/npm/npm.go internal/adapter/npm/npm_test.go cmd/shieldoo-gate/main.go
git commit -m "feat(npm): wire UpstreamResolver (default-only behaviour unchanged)"
```

Expected: all existing npm tests PASS (default path unchanged), build clean.

---

## Task 3: npm — packument fan-out + fail-closed rewrite + scoped-miss audit

**Files:**
- Modify: `internal/adapter/npm/npm.go` (metadata handlers + `proxyUpstreamRewrite`)
- Test: `internal/adapter/npm/npm_test.go`

> **Helper:** add `proxyOrigin(r)` near the handlers:
> ```go
> func proxyOrigin(r *http.Request) string {
> 	scheme := "http"
> 	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
> 		scheme = "https"
> 	}
> 	return scheme + "://" + r.Host
> }
> ```

- [ ] **Step 1: Write failing tests**

Add a multi-index helper + tests to `internal/adapter/npm/npm_test.go` (mirror `newMultiIndexAdapter` from `pypi_test.go`):

```go
func newMultiIndexNPM(t *testing.T, defaultURL string, extras []config.UpstreamIndex) *npm.NPMAdapter {
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
	return npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: defaultURL, ExtraIndexes: extras}, config.TagMutabilityConfig{})
}

func TestNPMAdapter_ExtraIndexPackument_RewritesTarballThroughProxy(t *testing.T) {
	var corp *httptest.Server
	corp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mycompany-lib" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"mycompany-lib","versions":{"1.0.0":{"dist":{"tarball":"` +
				corp.URL + `/mycompany-lib/-/mycompany-lib-1.0.0.tgz"}}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexNPM(t, "https://registry.invalid", []config.UpstreamIndex{{Name: "private", URL: corp.URL}})
	req := httptest.NewRequest(http.MethodGet, "/mycompany-lib", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `/mycompany-lib/-/mycompany-lib-1.0.0.tgz`)
	assert.NotContains(t, rec.Body.String(), corp.URL) // serving-host origin rewritten away
}

func TestNPMAdapter_ScopedMiss_Returns404AndAudits(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexNPM(t, "https://registry.invalid", []config.UpstreamIndex{
		{Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/mycompany-secret", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestNPMAdapter_ExtraIndexForeignTarball_FailsClosed(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mycompany-lib" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"versions":{"1.0.0":{"dist":{"tarball":"https://evil.cdn/x-1.0.0.tgz"}}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexNPM(t, "https://registry.invalid", []config.UpstreamIndex{{Name: "private", URL: corp.URL}})
	req := httptest.NewRequest(http.MethodGet, "/mycompany-lib", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code) // fail closed
}
```

- [ ] **Step 2: Implement the fan-out**

Replace `proxyUpstreamRewrite` with an index-aware fan-out and route the metadata handlers through it. Add to `npm.go`:

```go
// serveMetadataFanOut tries each resolved index for the package's metadata,
// rewriting the FIRST index that has it (200) so downloads route through the
// proxy. The default index uses the legacy serving-origin string replace
// (byte-identical to today); extra indexes use the JSON-aware fail-closed
// RewriteNPMPackumentTarballs. A claimed-namespace miss → 404 + audit.
func (a *NPMAdapter) serveMetadataFanOut(w http.ResponseWriter, r *http.Request, pkg, path string) {
	for _, idx := range a.resolver.ResolveForPackage(pkg) {
		served, err := a.tryServeMetadata(w, r, idx, path)
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
	if claimants := a.resolver.ClaimingIndexNames(pkg); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemNPM), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		safe := strings.NewReplacer("/", "_", "@", "").Replace(pkg)
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, safe),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index package not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	adapter.WriteJSONError(w, http.StatusNotFound, adapter.ErrorResponse{Error: "not found", Artifact: pkg})
}

// tryServeMetadata fetches one index's metadata at path. Returns (true,nil) when
// served (200, rewritten + relayed); (false,nil) on 404; (false,err) on
// transport / non-200 / rewrite error. A rewrite failure for an EXTRA index is
// FAIL CLOSED: it writes a 502 and returns (true,nil) so no other index is tried.
func (a *NPMAdapter) tryServeMetadata(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, path string) (bool, error) {
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
		return false, fmt.Errorf("npm: index %q returned %d", idx.Name, resp.StatusCode)
	}
	const maxMetadataSize = 200 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("npm: index %q metadata exceeds size limit", idx.Name)
	}

	var rewritten []byte
	if idx.Name == "" {
		// DEFAULT index: legacy serving-origin string replace (byte-identical).
		old := []byte(`"` + a.upstreamURL + "/")
		rewritten = []byte(strings.ReplaceAll(string(body), string(old), `"`+proxyOrigin(r)+"/"))
	} else {
		var rerr error
		rewritten, rerr = adapter.RewriteNPMPackumentTarballs(body, idx, proxyOrigin(r))
		if rerr != nil {
			log.Error().Err(rerr).Str("index", idx.Name).Msg("SECURITY: npm packument rewrite failed, refusing to serve")
			http.Error(w, "upstream metadata could not be safely rewritten", http.StatusBadGateway)
			return true, nil
		}
	}
	relayHeaders(w, resp, idx.Name)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rewritten)
	return true, nil
}

// relayHeaders copies upstream headers. Extra (low-trust) indexes get an
// allowlist only (Content-Type/ETag/Last-Modified); the default index relays all
// (minus Content-Length, which the rewrite changed).
func relayHeaders(w http.ResponseWriter, resp *http.Response, indexName string) {
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

Change the metadata handlers to call `serveMetadataFanOut` instead of `proxyUpstreamRewrite`:
- `handlePackageMetadata` → `a.serveMetadataFanOut(w, r, pkg, "/"+pkg)`
- `handleScopedMetadata` → `a.serveMetadataFanOut(w, r, "@"+scope+"/"+pkg, "/@"+scope+"/"+pkg)`

> Leave `handleVersionMetadata` / `handleScopedVersionMetadata` on `proxyUpstream` for the **default** index but make them resolver-aware in Task 4 only if needed — npm `install` resolves via the full packument (`/{pkg}`), which IS rewritten here; the per-version manifest is not used for tarball resolution. Document this as a known limitation (matches PyPI's root `/simple/` default-only limitation).

Delete `proxyUpstreamRewrite` if no caller remains (CLAUDE.md cleanup discipline).

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/npm/ -v && go build ./...
git add internal/adapter/npm/npm.go internal/adapter/npm/npm_test.go
git commit -m "feat(npm): multi-index packument fan-out + fail-closed tarball rewrite + scoped-miss audit"
```

---

## Task 4: npm — download index recovery + namespaced artifact IDs + auth

**Files:**
- Modify: `internal/adapter/npm/npm.go` (`downloadScanServe`, tarball handlers, `downloadToTemp`)
- Test: `internal/adapter/npm/npm_test.go`

> **Index recovery (design):** the npm download route already carries the package id, so recover index identity by re-running `ResolveForPackage(pkg)` and taking the **first** resolved index (deterministic per package). No `/ext-packages/` route.

- [ ] **Step 1: Write the failing test**

```go
func TestNPMAdapter_ExtraIndexTarballDownload_ScansAndNamespaces(t *testing.T) {
	var sentAuth string
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentAuth = r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/mycompany-lib-1.0.0.tgz") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("dummy-tgz-bytes"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_NPM_CORP_TOK", "tok-xyz")
	a := newMultiIndexNPM(t, "https://registry.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_NPM_CORP_TOK"},
	}})
	req := httptest.NewRequest(http.MethodGet, "/mycompany-lib/-/mycompany-lib-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code) // no scanners → clean → served
	assert.Equal(t, "Bearer tok-xyz", sentAuth)
	status, err := adapter.GetArtifactStatus(a.DB(), "npm__corp:mycompany-lib:1.0.0")
	require.NoError(t, err)
	require.NotNil(t, status)
}
```

Add a test-only DB accessor to `npm.go` if absent:

```go
// DB exposes the adapter's database handle for tests.
func (a *NPMAdapter) DB() *config.GateDB { return a.db }
```

- [ ] **Step 2: Recover the index on download**

In `handleTarballDownload` / `handleScopedTarballDownload`, resolve the serving index and build the real upstream tarball URL + auth + namespaced eco. Change `downloadScanServe`'s signature to accept the resolved index:

```go
func (a *NPMAdapter) handleTarballDownload(w http.ResponseWriter, r *http.Request) {
	pkg := chi.URLParam(r, "package")
	tarball := chi.URLParam(r, "tarball")
	idx := a.firstIndexFor(pkg)
	upstreamURL := strings.TrimRight(idx.URL, "/") + "/" + pkg + "/-/" + tarball
	a.downloadScanServe(w, r, upstreamURL, pkg, tarball, idx)
}

// firstIndexFor returns the first resolved index for a package (deterministic),
// or the default index if resolution is empty (scoped-miss tarball — the
// download will 502 on the absent upstream, which is correct: no public fallback).
func (a *NPMAdapter) firstIndexFor(pkg string) adapter.ResolvedIndex {
	if idxs := a.resolver.ResolveForPackage(pkg); len(idxs) > 0 {
		return idxs[0]
	}
	return adapter.ResolvedIndex{} // default
}
```

(Scoped variant mirrors this with `fullPkg := "@"+scope+"/"+pkg`.)

In `downloadScanServe`, add `idx adapter.ResolvedIndex` and:
- build the namespaced eco + artifact ID:
  ```go
  eco := adapter.NamespacedEcosystem(string(scanner.EcosystemNPM), idx.Name)
  safeNamePart := strings.NewReplacer("/", "_", "@", "").Replace(pkgName)
  artifactID := fmt.Sprintf("%s:%s:%s", eco, safeNamePart, version)
  ```
- keep `scanArtifact.Ecosystem = scanner.EcosystemNPM` (the bare eco — the cache/SBOM key uses the namespaced **artifactID**; the scanner eco stays canonical for typosquat/version-diff semantics, matching PyPI);
- pass `a.resolver.AuthHeader(idx)` to the download by switching `downloadToTemp` → an auth-aware variant:
  ```go
  tmpPath, size, sha, err := downloadToTempAuthed(pctx, upstreamURL, a.resolver.AuthHeader(idx), a.httpClient)
  ```
  Add `downloadToTempAuthed` (copy `downloadToTemp`, add the `Authorization` header when non-empty; the resolver's redirect-safe client is NOT used here — downloads use the 5-min `httpClient`; instead set the header directly and rely on the existing client). Replace the single caller; keep `downloadToTemp` only if another caller remains.

> **Auth on the download client:** the adapter's `httpClient` (`NewProxyHTTPClient`) has no redirect auth-strip. To avoid leaking the token on a cross-host redirect, build the download client for npm via `adapter.NewRedirectSafeClient(5 * time.Minute)` (Phase 2 helper) and use it for authed downloads. Simplest: change `a.httpClient` construction in the constructor to `adapter.NewRedirectSafeClient(5 * time.Minute)` (it is a superset — adds redirect safety, same timeout). Verify the existing tarball tests still pass.

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/npm/ -v && go build ./...
git add internal/adapter/npm/npm.go internal/adapter/npm/npm_test.go
git commit -m "feat(npm): download index recovery (re-resolve) + namespaced artifact IDs + per-index auth"
```

---

## Task 5: npm — config.example.yaml + example project

**Files:**
- Modify: `config.example.yaml`
- Create: `examples/npm-private-registry/README.md`, `examples/npm-private-registry/.npmrc.example`

- [ ] **Step 1: Document the schema** — add an `npm` multi-index block to `config.example.yaml` mirroring the PyPI one (default + unscoped public vendor registry + scoped private registry with env-var `auth`; note `files_host` is **PyPI-only** and ignored for npm — npm tarballs share the registry origin).

- [ ] **Step 2: Example project** — `examples/npm-private-registry/README.md` documenting: configure `upstreams.npm.extra_indexes` with a scoped private registry (env-var auth), point `.npmrc` `registry=` at the gate, `npm install` the private package **through** the gate (scanned + cached under `npm__<index>`, not bypassed). Reference `tests/e2e-shell/test_npm_multi_index.sh` as the executable spec. Add to `examples/README.md` index.

- [ ] **Step 3: Verify + commit**

```bash
make build && make lint && make test
git add config.example.yaml examples/npm-private-registry/ examples/README.md
git commit -m "docs(npm): document multi-index config + private-registry example"
```

---

## Task 6: NuGet — resolver wiring (default-only behaviour unchanged)

Mirror **Task 2** for `internal/adapter/nuget/nuget.go`:
- struct gains `resolver *adapter.UpstreamResolver`;
- constructor accepts `config.UpstreamSet`, `defaultURL := upstreams.DefaultOr("https://api.nuget.org")`, builds the resolver for ecosystem `"nuget"`;
- `main.go`: drop `nugetUpstream`, pass `cfg.Upstreams.NuGet`;
- migrate the nuget test setup helper to the new constructor.

Commit: `feat(nuget): wire UpstreamResolver (default-only behaviour unchanged)`.

---

## Task 7: NuGet — registration fan-out + fail-closed rewrite + scoped-miss audit

**Files:**
- Modify: `internal/adapter/nuget/nuget.go` (`handleRegistration`, `proxyUpstreamRewrite`)
- Test: `internal/adapter/nuget/nuget_test.go`

> **Service index (`/v3/index.json`)** stays default-only (it is index-wide, not per-package) — it keeps today's rewrite against the default upstream. **Registration (`/v3/registration/{id}/index.json`)** carries the package id → fan out across indexes. This mirrors PyPI's "root `/simple/` is default-only; per-package resolves."

- [ ] **Step 1: Write failing tests** (mirror npm Task 3): `newMultiIndexNuGet` helper; `TestNuGetAdapter_ExtraIndexRegistration_RewritesThroughProxy` (private feed serves a registration with same-host `@id`/`packageContent`; assert the body no longer contains the feed origin and contains the proxy origin); `TestNuGetAdapter_ScopedMiss_Returns404AndAudits`; `TestNuGetAdapter_ExtraIndexForeignPackageContent_FailsClosed` (feed registration embeds a foreign `packageContent` → expect 502).

- [ ] **Step 2: Implement the fan-out** in `handleRegistration`:

```go
func (a *NuGetAdapter) handleRegistration(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := adapter.ValidatePackageName(id); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid package id", Reason: err.Error()})
		return
	}
	if a.blockIfTyposquat(w, r, id, "") {
		return
	}
	path := "/v3/registration/" + id + "/index.json"
	for _, idx := range a.resolver.ResolveForPackage(id) {
		served, err := a.tryServeRegistration(w, r, idx, path)
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
	if claimants := a.resolver.ClaimingIndexNames(id); len(claimants) > 0 {
		a.resolver.ObserveScopedMiss()
		eco := adapter.NamespacedEcosystem(string(scanner.EcosystemNuGet), claimants[0])
		md, _ := json.Marshal(map[string]any{"claiming_indexes": claimants})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:    model.EventBlocked,
			ArtifactID:   fmt.Sprintf("%s:%s:*", eco, id),
			ClientIP:     r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Reason:       "scoped private-index package not found on any claiming index (no public fallback)",
			MetadataJSON: string(md),
		})
	}
	adapter.WriteJSONError(w, http.StatusNotFound, adapter.ErrorResponse{Error: "not found", Artifact: id})
}

// tryServeRegistration fetches one index's registration. DEFAULT index: legacy
// serving-origin string replace (byte-identical). EXTRA index: string-replace the
// serving origin to the proxy origin, THEN AssertNoForeignNuGetDownloadURLs —
// fail closed (502) if any packageContent/@id still points at a foreign host.
func (a *NuGetAdapter) tryServeRegistration(w http.ResponseWriter, r *http.Request, idx adapter.ResolvedIndex, path string) (bool, error) {
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
		return false, fmt.Errorf("nuget: index %q returned %d", idx.Name, resp.StatusCode)
	}
	const maxMetadataSize = 200 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
	if err != nil {
		return false, err
	}
	if int64(len(body)) > maxMetadataSize {
		return false, fmt.Errorf("nuget: index %q metadata exceeds size limit", idx.Name)
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	proxyOrigin := scheme + "://" + r.Host
	servingOrigin := strings.TrimRight(idx.URL, "/")
	rewritten := strings.ReplaceAll(string(body), servingOrigin+"/", proxyOrigin+"/")

	relayAllow := false
	if idx.Name == "" {
		// DEFAULT index: relay headers, no fail-closed parse (byte-identical path).
		relayAllow = true
	} else {
		// EXTRA index: fail closed on any surviving foreign download/subpage URL.
		if err := adapter.AssertNoForeignNuGetDownloadURLs([]byte(rewritten), r.Host); err != nil {
			log.Error().Err(err).Str("index", idx.Name).Msg("SECURITY: nuget registration rewrite incomplete, refusing to serve")
			http.Error(w, "upstream metadata could not be safely rewritten", http.StatusBadGateway)
			return true, nil
		}
	}
	// header relay (allowlist for extra; full for default)
	if relayAllow {
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
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rewritten)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, rewritten)
	return true, nil
}
```

Delete `proxyUpstreamRewrite` if no caller remains (the service index `handleServiceIndex` HTTPS branch still uses it — keep it, but it now must target the **default** upstream explicitly; `a.upstreamURL` is the default, so it is unchanged).

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/adapter/nuget/ -v && go build ./...
git add internal/adapter/nuget/nuget.go internal/adapter/nuget/nuget_test.go
git commit -m "feat(nuget): multi-index registration fan-out + fail-closed rewrite + scoped-miss audit"
```

---

## Task 8: NuGet — download index recovery + namespaced IDs + auth

Mirror **npm Task 4** for `handleNupkgDownload` / `downloadScanServe`:
- recover the serving index via `idx := a.firstIndexFor(id)`; build `upstreamURL := strings.TrimRight(idx.URL,"/") + "/v3-flatcontainer/" + id + "/" + version + "/" + filename`;
- namespaced artifact ID: `eco := adapter.NamespacedEcosystem(string(scanner.EcosystemNuGet), idx.Name); artifactID := fmt.Sprintf("%s:%s:%s", eco, pkgID, version)`;
- authed download via `downloadToTempAuthed` + `adapter.AuthHeader(idx)`;
- switch the constructor's `httpClient` to `adapter.NewRedirectSafeClient(5 * time.Minute)`.
- test: `TestNuGetAdapter_ExtraIndexNupkgDownload_ScansAndNamespaces` (asserts `nuget__corp:<id>:<ver>` artifact row + `Bearer` auth forwarded).

Commit: `feat(nuget): download index recovery + namespaced artifact IDs + per-index auth`.

---

## Task 9: NuGet — config.example.yaml + example project

Mirror **npm Task 5**: add a `nuget` multi-index block to `config.example.yaml`; create `examples/nuget-private-feed/README.md` + `examples/nuget-private-feed/nuget.config.example` (a `<packageSources>` pointing at the gate). Add to `examples/README.md`. Verify `make build && make lint && make test`. Commit: `docs(nuget): document multi-index config + private-feed example`.

---

## Task 10: Config migration — npm/nuget repo configs → `default:` form (Phase 4b parity)

**Files:** `docker/config.yaml`, `examples/deploy/config.yaml`, `.deploy/config.yaml` (skip if gitignored/absent — CI-safe, per Phase 4b precedent), Helm `values.yaml` + `configmap.yaml`.

> Shape-only, **no behaviour change**, **no production `extra_indexes`** (prod stays a transparent pull-through proxy). Mirror exactly how Phase 4b migrated `pypi`/`docker`.

- [ ] **Step 1:** In each committed config, change `npm: "https://registry.npmjs.org"` → `npm:\n  default: "https://registry.npmjs.org"` and `nuget: "https://api.nuget.org"` → `nuget:\n  default: "https://api.nuget.org"`.
- [ ] **Step 2:** Run the Phase 4b config-validation regression test (`grep -rn "TestAllCommittedConfigs\|loadAndValidate" internal/config/` to find it) — it must still pass with the migrated configs.
- [ ] **Step 3:** Commit: `config(npm,nuget): restructure committed upstreams to default: form (multi-index ready)`.

---

## Task 11: E2E harness — private npm + NuGet feeds + multi-index scenarios

**Files:**
- Create: `tests/e2e-shell/fixtures/private-npm/` (packument JSON + tarball), `tests/e2e-shell/fixtures/private-nuget/` (service index + registration + flatcontainer .nupkg).
- Modify: `tests/e2e-shell/docker-compose.e2e.yml` (serve the new trees via the **existing** `private-index` Caddy server — add volume mounts + Caddyfile routes; reuse the test CA so the https-only invariant is preserved).
- Modify: `tests/e2e-shell/config.e2e.yaml` (npm + nuget multi-index).
- Create: `tests/e2e-shell/test_npm_multi_index.sh`, `tests/e2e-shell/test_nuget_multi_index.sh`.
- Modify: `tests/e2e-shell/run_all.sh` (register both).

> **Harness reuse:** the Phase 4 `private-index` Caddy server already serves an HTTPS tree at `https://private-index:8443` with the trusted test CA. Extend its `Caddyfile`/`www` to also serve npm packuments under `/<pkg>` and NuGet V3 under `/v3/...` + `/v3-flatcontainer/...`. Mount the new fixture subtrees into the same container.

- [ ] **Step 1: npm fixture** — `tests/e2e-shell/fixtures/private-npm/gen.sh` builds a tiny tarball `mycompany-npm-lib-1.0.0.tgz` (an `npm pack` of a 2-file package), computes its sha512 base64 `integrity` + sha1 `shasum`, and writes a packument `www-npm/mycompany-npm-lib/index.json` whose single version's `dist.tarball` is `https://private-index:8443/mycompany-npm-lib/-/mycompany-npm-lib-1.0.0.tgz` with the correct `integrity`/`shasum`. Commit the generated `www-npm/` tree + the tarball under `www-npm/mycompany-npm-lib/-/`.

- [ ] **Step 2: nuget fixture** — `tests/e2e-shell/fixtures/private-nuget/gen.sh` builds a minimal `mycompany.nuget.lib.1.0.0.nupkg` (a zip with a `.nuspec`), and writes a V3 `registration/mycompany.nuget.lib/index.json` whose `packageContent` is `https://private-index:8443/v3-flatcontainer/mycompany.nuget.lib/1.0.0/mycompany.nuget.lib.1.0.0.nupkg` and the flatcontainer `.nupkg` + `index.json` (versions list). Commit the tree.

- [ ] **Step 3: Caddyfile + compose** — extend `fixtures/private-index/Caddyfile` with `handle_path` blocks (or add a second site) so `private-index:8443` also serves the npm + nuget trees; mount `./fixtures/private-npm/www-npm` and `./fixtures/private-nuget/www-nuget` into the `private-index` service.

- [ ] **Step 4: config.e2e.yaml** — replace the bare `npm:`/`nuget:` strings:

```yaml
  npm:
    default: "https://registry.npmjs.org"
    extra_indexes:
      - name: "private"
        url: "https://private-index:8443"
        packages: ["mycompany-*"]
  nuget:
    default: "https://api.nuget.org"
    extra_indexes:
      - name: "private"
        url: "https://private-index:8443"
        packages: ["mycompany.*"]
```

- [ ] **Step 5: test scripts** — `test_npm_multi_index.sh` defines `test_npm_multi_index()` (sourced; no `set -e`; uses `helpers.sh`). Scenarios:
  - **N1 back-compat:** a normal public package metadata still routes via default (`curl "$E2E_NPM_URL/is-odd"` returns 200 with a rewritten tarball pointing at the gate host).
  - **N2 release gate:** `curl "$E2E_NPM_URL/mycompany-npm-lib"` → packument with `dist.tarball` rewritten to the gate origin (assert it contains the gate host + path, NOT `private-index`); fetch that tarball through the gate (HTTP 200); assert an artifact row exists under ecosystem `npm__private` (the **non-negotiable scan+cache proof** — `api_jq "/api/v1/artifacts?ecosystem=npm__private"`). Optionally drive real `npm install --registry "$E2E_NPM_URL" mycompany-npm-lib` as a non-fatal client signal.
  - **N3 scoped-miss:** `curl -o /dev/null -w '%{http_code}' "$E2E_NPM_URL/mycompany-ghost"` → 404; assert a `BLOCKED` audit row under `npm__private:mycompany-ghost`.
  - **N4 foreign-host fail-closed (negative fixture):** a fixture packument `mycompany-evil` whose `dist.tarball` host is foreign → gate returns 502 (assert `%{http_code}` == 502; **no** artifact row).

  `test_nuget_multi_index.sh` mirrors this for the registration endpoint + `/v3-flatcontainer/` download + `nuget__private` ecosystem (`mycompany.nuget.lib`, scoped by `mycompany.*`); the scoped-miss uses `mycompany.ghost`; the foreign-host negative fixture asserts 502.

- [ ] **Step 6: register** in `run_all.sh` (source both files; call `test_npm_multi_index` after `test_npm`, `test_nuget_multi_index` after `test_nuget`).

- [ ] **Step 7: run** (logfile convention):

```bash
make test-e2e-containerized > /tmp/e2e-multi.log 2>&1; tail -n 120 /tmp/e2e-multi.log
```

Expected: N1–N4 + the nuget mirror PASS alongside the existing PyPI multi-index + all back-compat suites. **The npm__private / nuget__private artifact-row assertions are the hard release gate** — if either fails, a private artifact was served without scanning (full bypass) and the phase is NOT done.

- [ ] **Step 8: commit**

```bash
git add tests/e2e-shell/
git commit -m "test(e2e): npm + nuget multi-index scenarios (scanned+cached, scoped-miss, foreign-host fail-closed)"
```

---

## Task 12: Docs + security review

- [ ] **Step 1:** Update `docs/` npm + nuget adapter pages with a "Multi-upstream indexes" section (resolution order, scoping, `eco__<index>` namespacing, download index recovery via re-resolution, fail-closed rewrite, the npm version-manifest + nuget service-index default-only limitations). Link from `docs/index.md` if not already.
- [ ] **Step 2:** Run the **security-code-review** skill on the npm + nuget diff (mandate (d)): confirm (a) foreign download-host fail-closed, (b) non-JSON fail-closed, (c) real JSON parser, (d) no token leak on redirect (redirect-safe client), no header-relay injection from extra indexes, and the scoped-miss never falls through to public.
- [ ] **Step 3:** Commit docs: `docs(npm,nuget): document multi-upstream-index behaviour + limitations`.

---

## Phase 5 done-when

- [ ] npm + nuget default-only config behaves byte-identically to pre-feature (all legacy adapter tests green).
- [ ] npm packument / nuget registration resolve across indexes (ordered fallback + glob scoping); first hit serves; extra-index download URLs rewrite through the proxy **fail-closed** (foreign download host → 502; non-JSON → 502).
- [ ] Download legs recover the serving index by re-resolution, carry per-index env-var auth (redirect-safe), and store artifacts under `npm__<index>` / `nuget__<index>`.
- [ ] Scoped-namespace miss → 404 (no public fallback) + namespaced `BLOCKED` audit + `upstream_scoped_miss_total` metric.
- [ ] Committed configs migrated to `default:` form (no prod `extra_indexes`); config-validation regression green.
- [ ] `make build && make lint && make test` green.
- [ ] **`make test-e2e-containerized` green, including the new npm__private / nuget__private scan+cache release-gate assertions and the foreign-host fail-closed negatives.**
- [ ] Examples added; docs updated; implementation security review APPROVED.
