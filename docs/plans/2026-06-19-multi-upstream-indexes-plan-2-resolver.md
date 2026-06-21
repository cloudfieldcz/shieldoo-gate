# Multi-Upstream Indexes — Phase 2: Shared Resolver

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/adapter/upstream_set.go` — the non-Docker analogue of Docker's `RegistryResolver`. It performs ordered-fallback + glob-scoped routing, supplies per-index upstream auth, server-side files-host lookup (SSRF control), a metadata HTTP client with an explicit credential-stripping `CheckRedirect`, and a per-index circuit breaker. All logic is unit-testable in isolation; no adapter consumes it yet (Phase 3+).

**Architecture:** `UpstreamResolver` is constructed from a `config.UpstreamSet`. `ResolveForPackage(canonicalName)` returns the ordered `[]ResolvedIndex` to try (scoped indexes only when a pattern matches; otherwise default-then-extras), skipping indexes whose breaker is open. The resolver owns a short-timeout metadata `*http.Client` (distinct from adapters' 5-minute download client) whose `CheckRedirect` strips `Authorization` on any host/scheme change and refuses non-https credentialed redirects. `NamespacedEcosystem(eco, index)` (package-level) produces the artifact-ID eco segment.

**Tech Stack:** Go 1.25, `net/http`, `path/filepath` (glob), `github.com/prometheus/client_golang` (metrics), `github.com/stretchr/testify`, `net/http/httptest` (redirect tests).

**Index:** [`plan-index.md`](./2026-06-19-multi-upstream-indexes-plan-index.md)

---

## File structure

- **Create:** `internal/adapter/upstream_set.go` — `UpstreamResolver`, `ResolvedIndex`, `NamespacedEcosystem`, breaker, redirect-safe client.
- **Create:** `internal/adapter/upstream_set_test.go` — unit tests (ordering, scoping, auth, files-host, SSRF, redirect strip, breaker).
- **Modify:** `internal/adapter/metrics.go` — add the resolver metrics.

Depends on Phase 1 types (`config.UpstreamSet`, `UpstreamIndex`, `UpstreamAuth`).

---

## Task 1: `NamespacedEcosystem` artifact-ID helper

**Files:**
- Create: `internal/adapter/upstream_set.go`
- Test: `internal/adapter/upstream_set_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/adapter/upstream_set_test.go`:

```go
package adapter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamespacedEcosystem_DefaultIndex_BareEco(t *testing.T) {
	// Empty index name = default upstream → unchanged eco (preserves existing cache/IDs).
	assert.Equal(t, "pypi", NamespacedEcosystem("pypi", ""))
}

func TestNamespacedEcosystem_ExtraIndex_DoubleUnderscore(t *testing.T) {
	assert.Equal(t, "pypi__corp", NamespacedEcosystem("pypi", "corp"))
	assert.Equal(t, "npm__hexaly", NamespacedEcosystem("npm", "hexaly"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/adapter/ -run TestNamespacedEcosystem -v`
Expected: FAIL to compile — `undefined: NamespacedEcosystem`.

- [ ] **Step 3: Implement the helper**

Create `internal/adapter/upstream_set.go`:

```go
package adapter

// NamespacedEcosystem folds an upstream-index identity into the ecosystem
// segment of an artifact ID. The default index (empty name) keeps the bare
// ecosystem, preserving existing cache layout, audit, and SBOM history. An
// extra index `corp` for `pypi` becomes `pypi__corp`.
//
// The "__" separator is valid under the cache layer's validNameRe
// (^[a-zA-Z0-9._\-]+$), so no cache backend (local/S3/Azure/GCS) needs changes —
// they isolate on the eco segment on disk/key already. Index names are validated
// to ^[a-z0-9-]+$ at config load, so the "__" boundary is never ambiguous.
func NamespacedEcosystem(eco, indexName string) string {
	if indexName == "" {
		return eco
	}
	return eco + "__" + indexName
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/adapter/ -run TestNamespacedEcosystem -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go
git commit -m "feat(adapter): add NamespacedEcosystem artifact-ID helper"
```

---

## Task 2: `UpstreamResolver` construction + ordered/scoped `ResolveForPackage`

**Files:**
- Modify: `internal/adapter/upstream_set.go`
- Test: `internal/adapter/upstream_set_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/adapter/upstream_set_test.go`:

```go
import (
	// (add to the existing import block)
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/stretchr/testify/require"
)

func newTestResolver(t *testing.T, set config.UpstreamSet) *UpstreamResolver {
	t.Helper()
	r, err := NewUpstreamResolver("pypi", set)
	require.NoError(t, err)
	return r
}

func indexNames(idxs []ResolvedIndex) []string {
	out := make([]string, len(idxs))
	for i, x := range idxs {
		out[i] = x.Name
	}
	return out
}

func TestResolveForPackage_DefaultOnly_ReturnsDefaultUnnamed(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{Default: "https://pypi.org"})
	got := r.ResolveForPackage("requests")
	require.Len(t, got, 1)
	assert.Equal(t, "", got[0].Name) // default index has empty name
	assert.Equal(t, "https://pypi.org", got[0].URL)
}

func TestResolveForPackage_Unscoped_DefaultFirstThenExtrasInOrder(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "hexaly", URL: "https://pip.hexaly.com/hexaly/"},
			{Name: "mirror", URL: "https://mirror.example.com/"},
		},
	})
	got := r.ResolveForPackage("hexaly")
	assert.Equal(t, []string{"", "hexaly", "mirror"}, indexNames(got))
}

func TestResolveForPackage_ScopedMatch_OnlyScopedIndexNoFallback(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://corp.example.com/", Packages: []string{"mycompany-*"}},
		},
	})
	got := r.ResolveForPackage("mycompany-secret")
	require.Len(t, got, 1)
	assert.Equal(t, "corp", got[0].Name) // scoped match → ONLY corp, no default fallback
}

func TestResolveForPackage_ScopedMultiple_AllMatchingInOrder(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp-a", URL: "https://a.example.com/", Packages: []string{"shared-*"}},
			{Name: "corp-b", URL: "https://b.example.com/", Packages: []string{"shared-*"}},
		},
	})
	got := r.ResolveForPackage("shared-thing")
	assert.Equal(t, []string{"corp-a", "corp-b"}, indexNames(got))
}

func TestResolveForPackage_NoScopeMatch_FallsThroughToDefaultAndUnscoped(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://corp.example.com/", Packages: []string{"mycompany-*"}},
			{Name: "hexaly", URL: "https://pip.hexaly.com/hexaly/"},
		},
	})
	got := r.ResolveForPackage("requests")
	// corp is scoped and does NOT match → excluded; default + unscoped hexaly remain.
	assert.Equal(t, []string{"", "hexaly"}, indexNames(got))
}

func TestResolveForPackage_CanonicalisedBeforeMatch(t *testing.T) {
	// PyPI canonicalises Foo.Bar → foo-bar before glob matching.
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://corp.example.com/", Packages: []string{"my-co-*"}},
		},
	})
	got := r.ResolveForPackage("My_Co.Widget") // canonical → my-co-widget
	require.Len(t, got, 1)
	assert.Equal(t, "corp", got[0].Name)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/ -run TestResolveForPackage -v`
Expected: FAIL to compile — `undefined: NewUpstreamResolver`, `undefined: ResolvedIndex`.

- [ ] **Step 3: Implement resolver + `ResolveForPackage`**

Add to `internal/adapter/upstream_set.go` (extend imports with `fmt`, `path/filepath`, `strings`, `sync`, `time`, `net/http`, and `github.com/cloudfieldcz/shieldoo-gate/internal/config`, `github.com/cloudfieldcz/shieldoo-gate/internal/scanner`):

```go
// ResolvedIndex is one upstream to try for a package, in fallback order.
// The default index has Name "" and FilesHost "" (the adapter applies its own default).
type ResolvedIndex struct {
	Name      string
	URL       string
	FilesHost string
	authType  string // "bearer" | "basic" | ""
	tokenEnv  string
}

type resolvedIndexInternal struct {
	ResolvedIndex
	packages []string // glob scope; empty = unscoped
}

// UpstreamResolver routes bare-name package requests across a default upstream
// and ordered extra indexes, with optional per-index glob scoping. It is the
// non-Docker analogue of docker.RegistryResolver.
type UpstreamResolver struct {
	ecosystem string // e.g. "pypi" — used for name canonicalisation + metrics
	def       ResolvedIndex
	extras    []resolvedIndexInternal
	byName    map[string]resolvedIndexInternal

	client  *http.Client
	breaker *indexBreaker
}

// NewUpstreamResolver builds a resolver for one ecosystem from its UpstreamSet.
// The set is assumed already validated by config.validateUpstreamSet.
func NewUpstreamResolver(ecosystem string, set config.UpstreamSet) (*UpstreamResolver, error) {
	r := &UpstreamResolver{
		ecosystem: ecosystem,
		def:       ResolvedIndex{Name: "", URL: strings.TrimRight(set.Default, "/")},
		byName:    make(map[string]resolvedIndexInternal, len(set.ExtraIndexes)),
		breaker:   newIndexBreaker(5, 30*time.Second, time.Now),
	}
	for _, idx := range set.ExtraIndexes {
		ri := resolvedIndexInternal{
			ResolvedIndex: ResolvedIndex{
				Name:      idx.Name,
				URL:       strings.TrimRight(idx.URL, "/"),
				FilesHost: strings.TrimRight(idx.FilesHost, "/"),
			},
			packages: idx.Packages,
		}
		if idx.Auth != nil {
			ri.authType = idx.Auth.Type
			ri.tokenEnv = idx.Auth.TokenEnv
		}
		r.extras = append(r.extras, ri)
		r.byName[idx.Name] = ri
	}
	r.client = newMetadataClient()
	return r, nil
}

// canonical returns the ecosystem-canonical package name for glob matching.
func (r *UpstreamResolver) canonical(name string) string {
	return scanner.CanonicalPackageName(scanner.Ecosystem(r.ecosystem), name)
}

// ResolveForPackage returns the ordered indexes to try for a package name.
//
//   - If the name is CLAIMED (any scoped index's globs match the canonical name)
//     → return ONLY the claiming indexes that are not breaker-open, in config
//     order. NEVER fall back to the default/public index — a claimed namespace is
//     never silently shadowed.
//   - Otherwise → default first, then unscoped extra indexes in config order.
//
// Breaker-open indexes are skipped. CRITICAL: "claimed" is decided independently
// of the breaker. If every claiming index has an open breaker, the result is an
// EMPTY list (the handler then 404s — a scoped miss), NOT a public fallback. An
// earlier draft gated on the breaker-filtered list being non-empty, which would
// have fallen through to public when the private index was down — a
// dependency-confusion regression. Fixed (security review finding #1).
func (r *UpstreamResolver) ResolveForPackage(name string) []ResolvedIndex {
	canon := r.canonical(name)

	claimed := false
	var scoped []ResolvedIndex
	for _, e := range r.extras {
		if len(e.packages) == 0 {
			continue
		}
		if matchAny(e.packages, canon) {
			claimed = true
			if !r.breaker.open(e.Name) {
				scoped = append(scoped, e.ResolvedIndex)
			}
		}
	}
	if claimed {
		return scoped // may be empty → scoped miss (404); NEVER public fallback
	}

	var out []ResolvedIndex
	if r.def.URL != "" {
		out = append(out, r.def) // default breaker is never opened (it is the baseline)
	}
	for _, e := range r.extras {
		if len(e.packages) == 0 && !r.breaker.open(e.Name) {
			out = append(out, e.ResolvedIndex)
		}
	}
	return out
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if ok, _ := filepath.Match(p, s); ok {
			return true
		}
	}
	return false
}
```

> **Note on `scanner.CanonicalPackageName`:** verified to exist (`pypi.CanonicalName` wraps it). For ecosystems whose canonicalisation differs (npm scopes, NuGet case-fold, Go `!`-encoding), `scanner.Ecosystem(r.ecosystem)` selects the right rule. This is exercised per ecosystem in Phases 4–6.

- [ ] **Step 4: Add the circuit breaker + metadata client stubs to compile**

Still in `internal/adapter/upstream_set.go`, add:

```go
// indexBreaker is a per-index consecutive-failure circuit breaker. After
// `threshold` consecutive failures an index is skipped until `cooldown` elapses.
type indexBreaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	now       func() time.Time
	fails     map[string]int
	openUntil map[string]time.Time
}

func newIndexBreaker(threshold int, cooldown time.Duration, now func() time.Time) *indexBreaker {
	return &indexBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		now:       now,
		fails:     make(map[string]int),
		openUntil: make(map[string]time.Time),
	}
}

func (b *indexBreaker) open(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.openUntil[name]
	if !ok {
		return false
	}
	if b.now().Before(until) {
		return true
	}
	delete(b.openUntil, name) // cooldown elapsed → half-open (allow a probe)
	b.fails[name] = 0
	return false
}

// Record reports the outcome of a probe against an index. A nil err resets the
// failure count; a non-nil err increments it and opens the breaker at threshold.
func (b *indexBreaker) Record(name string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.fails[name] = 0
		delete(b.openUntil, name)
		return
	}
	b.fails[name]++
	if b.fails[name] >= b.threshold {
		b.openUntil[name] = b.now().Add(b.cooldown)
	}
}

// newMetadataClient is defined in Task 4 (redirect-safe). Placeholder forward-ref.
```

To keep this task compiling, temporarily add a minimal `newMetadataClient` (replaced in Task 4):

```go
func newMetadataClient() *http.Client { return &http.Client{Timeout: 10 * time.Second} }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/adapter/ -run TestResolveForPackage -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go
git commit -m "feat(adapter): UpstreamResolver ordered-fallback + glob scoping"
```

---

## Task 3: Auth header, files-host lookup, SSRF-safe index validation

**Files:**
- Modify: `internal/adapter/upstream_set.go`
- Test: `internal/adapter/upstream_set_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/adapter/upstream_set_test.go`:

```go
func TestAuthHeader_Bearer_ReadsEnv(t *testing.T) {
	t.Setenv("SGW_CORP_TOK", "abc123")
	r := newTestResolver(t, config.UpstreamSet{
		ExtraIndexes: []config.UpstreamIndex{{
			Name: "corp", URL: "https://corp.example.com/", Packages: []string{"corp-*"},
			Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_CORP_TOK"},
		}},
	})
	idxs := r.ResolveForPackage("corp-x")
	require.Len(t, idxs, 1)
	assert.Equal(t, "Bearer abc123", r.AuthHeader(idxs[0]))
}

func TestAuthHeader_Basic_ReadsEnv(t *testing.T) {
	t.Setenv("SGW_CORP_TOK", "dXNlcjpwYXNz")
	r := newTestResolver(t, config.UpstreamSet{
		ExtraIndexes: []config.UpstreamIndex{{
			Name: "corp", URL: "https://corp.example.com/", Packages: []string{"corp-*"},
			Auth: &config.UpstreamAuth{Type: "basic", TokenEnv: "SGW_CORP_TOK"},
		}},
	})
	idxs := r.ResolveForPackage("corp-x")
	assert.Equal(t, "Basic dXNlcjpwYXNz", r.AuthHeader(idxs[0]))
}

func TestAuthHeader_NoAuthOrMissingEnv_Empty(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{Default: "https://pypi.org"})
	assert.Equal(t, "", r.AuthHeader(r.ResolveForPackage("x")[0])) // default has no auth
}

func TestFilesHostFor_KnownIndex_ReturnsHost(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		ExtraIndexes: []config.UpstreamIndex{{
			Name: "corp", URL: "https://corp.example.com/", FilesHost: "https://files.corp.example.com/",
		}},
	})
	host, ok := r.FilesHostFor("corp")
	require.True(t, ok)
	assert.Equal(t, "https://files.corp.example.com/", host)
}

func TestFilesHostFor_DefaultEmptyName_OKEmptyHost(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{Default: "https://pypi.org"})
	host, ok := r.FilesHostFor("") // default index → ok, but empty (adapter uses its own default)
	assert.True(t, ok)
	assert.Equal(t, "", host)
}

func TestFilesHostFor_UnknownIndex_NotOK(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{Default: "https://pypi.org"})
	_, ok := r.FilesHostFor("../../etc") // forged / unknown → fail closed (SSRF control)
	assert.False(t, ok)
	_, ok = r.FilesHostFor("ghost")
	assert.False(t, ok)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/ -run 'TestAuthHeader|TestFilesHostFor' -v`
Expected: FAIL to compile — `undefined: (*UpstreamResolver).AuthHeader`, `FilesHostFor`.

- [ ] **Step 3: Implement auth + files-host**

Add to `internal/adapter/upstream_set.go` (add `"os"` and `"net/url"` to imports):

```go
// AuthHeader returns the Authorization header value for an index, or "" if the
// index has no auth or its token env var is unset. Never derived from a client
// request — credentials come only from the configured env var.
func (r *UpstreamResolver) AuthHeader(idx ResolvedIndex) string {
	if idx.tokenEnv == "" {
		return ""
	}
	tok := os.Getenv(idx.tokenEnv)
	if tok == "" {
		return ""
	}
	switch idx.authType {
	case "basic":
		return "Basic " + tok
	case "bearer":
		return "Bearer " + tok
	default:
		return "" // unknown type → fail closed (config validation should have caught it)
	}
}

// FilesHostFor returns the configured files host for an index name (PyPI only).
// For the default index ("") it returns ("", true) — the adapter supplies its
// own default CDN. For an unknown / forged name it returns ("", false) so the
// download handler can 404 BEFORE constructing any upstream URL (SSRF control).
func (r *UpstreamResolver) FilesHostFor(name string) (string, bool) {
	if name == "" {
		return "", true
	}
	idx, ok := r.byName[name]
	if !ok {
		return "", false
	}
	return idx.FilesHost, true
}

// IndexByName returns a resolved index by name (for the download leg's auth lookup).
func (r *UpstreamResolver) IndexByName(name string) (ResolvedIndex, bool) {
	if name == "" {
		return r.def, true
	}
	idx, ok := r.byName[name]
	if !ok {
		return ResolvedIndex{}, false
	}
	return idx.ResolvedIndex, true
}

var _ = url.Parse // url used by newMetadataClient (Task 4)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adapter/ -run 'TestAuthHeader|TestFilesHostFor' -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go
git commit -m "feat(adapter): per-index auth header + SSRF-safe files-host lookup"
```

---

## Task 4: Redirect-safe metadata HTTP client

**Files:**
- Modify: `internal/adapter/upstream_set.go` (replace the Task 2 placeholder `newMetadataClient`)
- Test: `internal/adapter/upstream_set_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/adapter/upstream_set_test.go` (add `net/http`, `net/http/httptest` to imports):

```go
func TestMetadataClient_StripsAuthOnHostChange(t *testing.T) {
	var gotAuth string
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound) // cross-host (and https→http) redirect
	}))
	defer redirector.Close()

	c := newMetadataClient()
	c.Transport = final.Client().Transport // trust the TLS test cert
	req, _ := http.NewRequest(http.MethodGet, redirector.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Empty(t, gotAuth, "Authorization must be stripped across host/scheme change")
}

func TestMetadataClient_RefusesNonHTTPSCredentialedRedirect(t *testing.T) {
	// Redirect to a plain-http target while carrying credentials → error (fail closed).
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound) // http target
	}))
	defer redirector.Close()

	c := newMetadataClient()
	req, _ := http.NewRequest(http.MethodGet, redirector.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	_, err := c.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestMetadataClient_CapsRedirectDepth(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound) // infinite loop
	}))
	defer srv.Close()
	c := newMetadataClient()
	_, err := c.Get(srv.URL)
	require.Error(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/ -run TestMetadataClient -v`
Expected: FAIL — the placeholder client has no `CheckRedirect`, so auth is forwarded / http redirect is followed.

- [ ] **Step 3: Replace `newMetadataClient` with a redirect-safe implementation**

In `internal/adapter/upstream_set.go`, replace the placeholder `newMetadataClient` with the code below, and **remove the `var _ = url.Parse` placeholder from Task 3** — `net/url` is now genuinely used by `sameHostScheme`/`hostWithPort`:

```go
const (
	metadataProbeTimeout = 15 * time.Second
	maxRedirects         = 10
)

// newMetadataClient returns the HTTP client used for upstream METADATA probes
// (small, short timeout) — distinct from adapters' 5-minute artifact-download
// client. CheckRedirect, IN THIS ORDER (security review finding #3 — the refusal
// must run BEFORE the strip, or it becomes dead code):
//  1. refuse a credentialed redirect to a non-https target, regardless of host
//     (fail closed) — evaluated against the TARGET scheme before any strip;
//  2. strip Authorization on any host or scheme change (Go's stdlib only strips
//     on host change, missing same-host https→http downgrades), comparing hosts
//     with default ports normalised so :443/:80 don't cause spurious strips;
//  3. cap redirect depth.
func newMetadataClient() *http.Client {
	base := NewProxyHTTPClient(metadataProbeTimeout)
	base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("upstream: too many redirects (>%d)", maxRedirects)
		}
		prev := via[len(via)-1].URL
		cur := req.URL
		// (1) Refuse credentialed redirect to non-https — BEFORE stripping.
		if req.Header.Get("Authorization") != "" && cur.Scheme != "https" {
			return fmt.Errorf("upstream: refusing credentialed redirect to non-https %q", cur.Scheme)
		}
		// (2) Strip on host/scheme change (ports normalised).
		if !sameHostScheme(prev, cur) {
			req.Header.Del("Authorization")
		}
		return nil
	}
	return base
}

// sameHostScheme reports whether two URLs share scheme and host, treating an
// implicit default port as equal to its explicit form (e.g. example.com ==
// example.com:443 for https).
func sameHostScheme(a, b *url.URL) bool {
	if a.Scheme != b.Scheme {
		return false
	}
	return hostWithPort(a) == hostWithPort(b)
}

func hostWithPort(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + port
}
```

> With the corrected ordering (refuse-before-strip), the non-https refusal fires whenever the target
> scheme is not https AND `Authorization` is still set — independent of host. A same-host https→http
> downgrade therefore errors (credentials present, target http). `httptest.NewServer` can't easily
> produce a same-host scheme downgrade, so Step 4 drives `CheckRedirect` directly for a deterministic test.

- [ ] **Step 4: Make the non-https refusal test deterministic**

Replace `TestMetadataClient_RefusesNonHTTPSCredentialedRedirect` with a same-host scheme-downgrade simulation using a custom `CheckRedirect` invocation, since httptest can't easily produce a same-host https→http hop:

```go
func TestMetadataClient_RefusesNonHTTPSCredentialedRedirect(t *testing.T) {
	c := newMetadataClient()
	prev, _ := http.NewRequest(http.MethodGet, "https://idx.example.com/a", nil)
	next, _ := http.NewRequest(http.MethodGet, "http://idx.example.com/a", nil) // same host, downgraded scheme
	next.Header.Set("Authorization", "Bearer secret")
	err := c.CheckRedirect(next, []*http.Request{prev})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
	// Cross-host case strips first, so no error but header gone:
	cross, _ := http.NewRequest(http.MethodGet, "https://other.example.com/a", nil)
	cross.Header.Set("Authorization", "Bearer secret")
	require.NoError(t, c.CheckRedirect(cross, []*http.Request{prev}))
	assert.Empty(t, cross.Header.Get("Authorization"))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/adapter/ -run TestMetadataClient -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Expose the client + a probe helper**

Add to `internal/adapter/upstream_set.go`:

```go
// Client returns the resolver's metadata HTTP client (redirect-safe, short timeout).
func (r *UpstreamResolver) Client() *http.Client { return r.client }

// RecordProbe reports a metadata-probe outcome for an index so the circuit
// breaker can skip persistently-failing indexes. The default index ("") is never breakered.
func (r *UpstreamResolver) RecordProbe(indexName string, err error) {
	if indexName == "" {
		return
	}
	r.breaker.Record(indexName, err)
}
```

- [ ] **Step 7: Commit**

```bash
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go
git commit -m "feat(adapter): redirect-safe metadata client + probe breaker hook"
```

---

## Task 5: Circuit-breaker behaviour tests + resolver metrics

**Files:**
- Modify: `internal/adapter/metrics.go`
- Modify: `internal/adapter/upstream_set.go`
- Test: `internal/adapter/upstream_set_test.go`

- [ ] **Step 1: Write the failing breaker tests**

Add to `internal/adapter/upstream_set_test.go`:

```go
func TestBreaker_OpensAfterThresholdAndSkipsIndex(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{{Name: "flaky", URL: "https://flaky.example.com/"}},
	})
	r.breaker = newIndexBreaker(3, 30*time.Second, clock)

	for i := 0; i < 3; i++ {
		r.RecordProbe("flaky", assert.AnError)
	}
	// breaker open → flaky excluded from resolution
	assert.Equal(t, []string{""}, indexNames(r.ResolveForPackage("requests")))

	// after cooldown → half-open, flaky returns
	now = now.Add(31 * time.Second)
	assert.Equal(t, []string{"", "flaky"}, indexNames(r.ResolveForPackage("requests")))
}

func TestBreaker_ScopedIndexOpen_StillScopedMissNoPublicFallback(t *testing.T) {
	// Security regression guard (finding #1): a claimed namespace whose ONLY
	// claiming index has an open breaker must yield an EMPTY result (→ 404),
	// never fall through to the public default.
	now := time.Unix(0, 0)
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://corp.example.com/", Packages: []string{"mycompany-*"}},
		},
	})
	r.breaker = newIndexBreaker(2, 30*time.Second, func() time.Time { return now })
	r.RecordProbe("corp", assert.AnError)
	r.RecordProbe("corp", assert.AnError) // breaker open
	got := r.ResolveForPackage("mycompany-secret")
	assert.Empty(t, got, "claimed name with breaker-open index must NOT fall back to public default")
}

func TestBreaker_SuccessResetsFailureCount(t *testing.T) {
	now := time.Unix(0, 0)
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{{Name: "flaky", URL: "https://flaky.example.com/"}},
	})
	r.breaker = newIndexBreaker(3, 30*time.Second, func() time.Time { return now })
	r.RecordProbe("flaky", assert.AnError)
	r.RecordProbe("flaky", assert.AnError)
	r.RecordProbe("flaky", nil) // reset
	r.RecordProbe("flaky", assert.AnError)
	assert.Equal(t, []string{"", "flaky"}, indexNames(r.ResolveForPackage("x"))) // still closed
}
```

- [ ] **Step 2: Run tests to verify they fail then pass**

Run: `go test ./internal/adapter/ -run TestBreaker -v`
Expected: PASS (the breaker logic from Task 2 already supports this; if a test fails, fix `indexBreaker`). These tests lock in the behaviour.

- [ ] **Step 3: Add resolver metrics**

Append to `internal/adapter/metrics.go`:

```go
// upstreamIndexProbeTotal counts metadata-probe outcomes per ecosystem/index.
// result ∈ {hit, miss, error}. "hit" = index served the package; "miss" = 404;
// "error" = transport/timeout (feeds the circuit breaker).
var upstreamIndexProbeTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "shieldoo_gate_upstream_index_probe_total",
		Help: "Upstream multi-index metadata probe outcomes by ecosystem, index, and result.",
	},
	[]string{"ecosystem", "index", "result"},
)

// upstreamScopedMissTotal counts scoped-namespace lookups that found no serving
// index (404, no fallback). A rising count can indicate a compromised/unreachable
// private index masking a claimed namespace — also audited per request.
var upstreamScopedMissTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "shieldoo_gate_upstream_scoped_miss_total",
		Help: "Scoped multi-index package lookups that returned 404 with no fallback.",
	},
	[]string{"ecosystem"},
)
```

- [ ] **Step 4: Wire metric recording into the resolver**

Add to `internal/adapter/upstream_set.go`:

```go
// ObserveProbe records a probe-outcome metric and updates the breaker.
// result must be one of "hit", "miss", "error".
func (r *UpstreamResolver) ObserveProbe(indexName, result string) {
	label := indexName
	if label == "" {
		label = "default"
	}
	upstreamIndexProbeTotal.WithLabelValues(r.ecosystem, label, result).Inc()
	switch result {
	case "error":
		r.RecordProbe(indexName, errProbe)
	case "hit", "miss":
		r.RecordProbe(indexName, nil)
	}
}

// ObserveScopedMiss records that a scoped lookup found no serving index.
func (r *UpstreamResolver) ObserveScopedMiss() {
	upstreamScopedMissTotal.WithLabelValues(r.ecosystem).Inc()
}

var errProbe = fmt.Errorf("upstream: index probe failed")
```

- [ ] **Step 5: Full phase verification**

Run: `go test ./internal/adapter/ -v && make build && make lint`
Expected: all adapter tests PASS; build + lint clean. (No e2e — no adapter wires the resolver yet.)

- [ ] **Step 6: Commit**

```bash
git add internal/adapter/upstream_set.go internal/adapter/upstream_set_test.go internal/adapter/metrics.go
git commit -m "feat(adapter): index circuit breaker + probe/scoped-miss metrics"
```

---

## Phase 2 done-when

- [ ] `UpstreamResolver` resolves default-only, unscoped-ordered, and scoped-exclusive cases correctly.
- [ ] Names canonicalised before glob matching; scoped match → no default fallback.
- [ ] `AuthHeader` reads env-only credentials; never derived from client requests.
- [ ] `FilesHostFor` fails closed on unknown/forged index names (SSRF control).
- [ ] Metadata client strips `Authorization` on host/scheme change, refuses non-https credentialed redirects, caps redirect depth.
- [ ] Circuit breaker opens after threshold, half-opens after cooldown, resets on success; default index never breakered.
- [ ] Probe + scoped-miss metrics registered.
- [ ] `make build && make lint && make test` green; `go.mod`/docs unchanged (resolver doc lands in Phase 7).
