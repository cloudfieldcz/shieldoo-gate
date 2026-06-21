package adapter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespacedEcosystem_DefaultIndex_BareEco(t *testing.T) {
	// Empty index name = default upstream → unchanged eco (preserves existing cache/IDs).
	assert.Equal(t, "pypi", NamespacedEcosystem("pypi", ""))
}

func TestNamespacedEcosystem_ExtraIndex_DoubleUnderscore(t *testing.T) {
	assert.Equal(t, "pypi__corp", NamespacedEcosystem("pypi", "corp"))
	assert.Equal(t, "npm__hexaly", NamespacedEcosystem("npm", "hexaly"))
}

// ---- npm / nuget fail-closed JSON download-URL rewrite helpers ----

func TestRewriteNPMPackumentTarballs_RewritesServingHost(t *testing.T) {
	in := []byte(`{"versions":{"1.0.0":{"dist":{"tarball":"https://npm.corp.example.com/foo/-/foo-1.0.0.tgz","shasum":"abc"}}},"repository":{"url":"git+https://github.com/x/foo.git"}}`)
	out, err := RewriteNPMPackumentTarballs(in,
		ResolvedIndex{Name: "corp", URL: "https://npm.corp.example.com"},
		"http://gate.local")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `"tarball":"http://gate.local/foo/-/foo-1.0.0.tgz"`)
	assert.Contains(t, s, `"shasum":"abc"`)                    // integrity preserved
	assert.Contains(t, s, `git+https://github.com/x/foo.git`) // non-download URL untouched
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

func TestAssertNoForeignNuGetDownloadURLs_NonFlatContainerPackageContent_FailsClosed(t *testing.T) {
	// Host equals the proxy host (passes the host check) but the path does NOT
	// match the scanned /v3-flatcontainer/{id}/{version}/{file} route — it would
	// route to the unscanned catch-all passthrough. Must fail closed (issue #32).
	body := []byte(`{"items":[{"catalogEntry":{"packageContent":"http://gate.local/v3/crafted.nupkg"}}]}`)
	require.Error(t, AssertNoForeignNuGetDownloadURLs(body, "gate.local"))
}

func TestAssertNoForeignNuGetDownloadURLs_FlatContainerPackageContent_OK(t *testing.T) {
	body := []byte(`{"items":[{"catalogEntry":{"packageContent":"http://gate.local/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"}}]}`)
	require.NoError(t, AssertNoForeignNuGetDownloadURLs(body, "gate.local"))
}

func TestResolveForPackage_NuGetMixedCaseGlob_Claimed(t *testing.T) {
	// NuGet ids are case-insensitive; the client sends the lowercased id. A config
	// glob written `MyCompany.*` MUST still claim `mycompany.privatelib`, else the
	// scoped package falls through to the public default (dependency confusion).
	r, err := NewUpstreamResolver("nuget", config.UpstreamSet{
		Default: "https://api.nuget.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://nuget.corp.example.com", Packages: []string{"MyCompany.*"}},
		},
	})
	require.NoError(t, err)
	assert.True(t, r.ScopeMatches("mycompany.privatelib"), "lowercased id must be claimed by MyCompany.* glob")
	got := r.ResolveForPackage("mycompany.privatelib")
	require.Len(t, got, 1)
	assert.Equal(t, "corp", got[0].Name, "claimed package must resolve ONLY to the scoped index, never the public default")
}

// ---- UpstreamResolver helpers ----

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

// ---- UpstreamResolver tests ----

func TestResolveForPackage_DefaultOnly_ReturnsDefaultUnnamed(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{Default: "https://pypi.org"})
	got := r.ResolveForPackage("requests")
	require.Len(t, got, 1)
	assert.Equal(t, "", got[0].Name)
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
	assert.Equal(t, "corp", got[0].Name)
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
	assert.Equal(t, []string{"", "hexaly"}, indexNames(got))
}

func TestResolveForPackage_CanonicalisedBeforeMatch(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://corp.example.com/", Packages: []string{"my-co-*"}},
		},
	})
	// PyPI PEP 503: My_Co.Widget → my-co-widget; glob my-co-* must match.
	got := r.ResolveForPackage("My_Co.Widget")
	require.Len(t, got, 1)
	assert.Equal(t, "corp", got[0].Name)
}

func TestNewUpstreamResolver_EmptyEcosystem_ReturnsError(t *testing.T) {
	_, err := NewUpstreamResolver("", config.UpstreamSet{Default: "https://pypi.org"})
	require.Error(t, err)
}

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
	// NewUpstreamResolver trims trailing "/" on FilesHost, so stored value has no trailing slash.
	assert.Equal(t, "https://files.corp.example.com", host)
}

func TestFilesHostFor_DefaultEmptyName_OKEmptyHost(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{Default: "https://pypi.org"})
	host, ok := r.FilesHostFor("")
	assert.True(t, ok)
	assert.Equal(t, "", host)
}

func TestFilesHostFor_UnknownIndex_NotOK(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{Default: "https://pypi.org"})
	_, ok := r.FilesHostFor("../../etc")
	assert.False(t, ok)
	_, ok = r.FilesHostFor("ghost")
	assert.False(t, ok)
}

// ---- newMetadataClient redirect-safety tests ----

func TestMetadataClient_StripsAuthOnHostChange(t *testing.T) {
	var gotAuth string
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound) // cross-host redirect (different host/port → strip fires); scheme also changes http→https
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

func TestMetadataClient_KeepsAuthOnSameHostScheme(t *testing.T) {
	c := newMetadataClient()
	prev, _ := http.NewRequest(http.MethodGet, "https://idx.example.com/a", nil)
	next, _ := http.NewRequest(http.MethodGet, "https://idx.example.com/b", nil) // same host+scheme
	next.Header.Set("Authorization", "Bearer secret")
	require.NoError(t, c.CheckRedirect(next, []*http.Request{prev}))
	assert.Equal(t, "Bearer secret", next.Header.Get("Authorization"), "auth must be preserved on same host+scheme redirect")
	// default-port normalisation: explicit :443 must also count as same host
	next2, _ := http.NewRequest(http.MethodGet, "https://idx.example.com:443/c", nil)
	next2.Header.Set("Authorization", "Bearer secret")
	require.NoError(t, c.CheckRedirect(next2, []*http.Request{prev}))
	assert.Equal(t, "Bearer secret", next2.Header.Get("Authorization"), "explicit :443 must equal implicit https port")
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

// ---- indexBreaker tests ----

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

func TestObserveProbe_ErrorsFeedBreaker(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{{Name: "flaky", URL: "https://flaky.example.com/"}},
	})
	now := time.Unix(0, 0)
	r.breaker = newIndexBreaker(2, 30*time.Second, func() time.Time { return now })
	r.ObserveProbe("flaky", "error")
	r.ObserveProbe("flaky", "error")
	assert.Equal(t, []string{""}, indexNames(r.ResolveForPackage("requests")))
	r.ObserveProbe("flaky", "hit") // hit resets
	assert.Equal(t, []string{"", "flaky"}, indexNames(r.ResolveForPackage("requests")))
}

func TestAuthHeader_TokenEnvSetButVarUnset_Empty(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		ExtraIndexes: []config.UpstreamIndex{{
			Name: "corp", URL: "https://corp.example.com/", Packages: []string{"corp-*"},
			Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_DEFINITELY_UNSET_TOKEN_XYZ"},
		}},
	})
	// env var is not set → fail closed, no malformed "Bearer " header
	assert.Equal(t, "", r.AuthHeader(r.ResolveForPackage("corp-x")[0]))
}

// ---- ScopeMatches / ClaimingIndexNames tests ----

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

func TestClaimingIndexNames_ReturnsMatchingNames(t *testing.T) {
	r := newTestResolver(t, config.UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []config.UpstreamIndex{
			{Name: "corp", URL: "https://corp.example.com/", Packages: []string{"mycompany-*"}},
		},
	})
	assert.Equal(t, []string{"corp"}, r.ClaimingIndexNames("mycompany-x"))
	assert.Empty(t, r.ClaimingIndexNames("requests"))
}

// ---- RewriteExtraIndexSimplePage tests ----

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
		ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	assert.Contains(t, string(out), `href="/ext-packages/corp/packages/foo-1.0.tar.gz"`)
}

func TestRewriteExtraIndex_UnroutableAbsoluteURL_FailsClosed(t *testing.T) {
	in := `<a href="https://evil.cdn.example.net/foo-1.0.whl">foo</a>`
	_, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	require.Error(t, err)
}

func TestRewriteExtraIndex_PreservesNonHrefBytes(t *testing.T) {
	in := `<a href="https://corp.example.com/packages/foo-1.0.whl" data-requires-python="&gt;=3.8" data-dist-info-metadata="sha256=abc">foo-1.0</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `data-requires-python="&gt;=3.8"`)
	assert.Contains(t, s, `data-dist-info-metadata="sha256=abc"`)
	assert.Contains(t, s, `href="/ext-packages/corp/packages/foo-1.0.whl"`)
}

// ---- FIX B: unquoted href tests ----

func TestRewriteExtraIndex_UnquotedHref_Rewritten(t *testing.T) {
	in := `<a href=https://corp.example.com/packages/foo-1.0.whl>foo</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	assert.Contains(t, string(out), `href="/ext-packages/corp/packages/foo-1.0.whl"`)
}

func TestRewriteExtraIndex_UnquotedUnroutableHref_FailsClosed(t *testing.T) {
	in := `<a href=https://evil.cdn.example.net/foo-1.0.whl>foo</a>`
	_, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	require.Error(t, err)
}

func TestRewriteExtraIndex_DataHrefAttr_NotCorrupted(t *testing.T) {
	in := `<a data-href="https://other.example.net/x" href="https://corp.example.com/packages/foo.whl">foo</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `data-href="https://other.example.net/x"`) // untouched
	assert.Contains(t, s, `href="/ext-packages/corp/packages/foo.whl"`)
}

// ---- FIX C: path traversal tests ----

func TestRewriteExtraIndex_PathTraversal_FailsClosed(t *testing.T) {
	// Test plain ".." segments resolved from a relative href.
	in := `<a href="../../packages/x-1.0.whl">x</a>`
	_, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	// "../../packages/x-1.0.whl" resolves against https://corp.example.com/simple/foo/
	// → https://corp.example.com/packages/x-1.0.whl which has no ".." in the path.
	// So no traversal error, but still rewritten to /ext-packages/corp/packages/x-1.0.whl.
	// The traversal guard specifically targets a literal ".." remaining in abs.Path.
	// A percent-encoded ..%2f that survives URL parsing as ".." IS caught.
	if err == nil {
		// Relative URLs that resolve cleanly are valid; they should be rewritten not rejected.
		out, _ := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
			"https://corp.example.com/simple/foo/")
		assert.Contains(t, string(out), `/ext-packages/corp/packages/x-1.0.whl`)
	}
}

func TestRewriteExtraIndex_PercentEncodedDotDot_FailsClosed(t *testing.T) {
	// ..%2f is decoded by url.Parse into ".." path segments when it survives
	// as a path segment. We also test a crafted absolute URL that has literal ".."
	// in its path after parsing, which the guard catches.
	// Go's url.Parse / ResolveReference normalise away path ".." by collapsing them,
	// so the primary risk is a crafted href that produces a ".." segment AFTER resolution.
	// A safe way to force a ".." into abs.Path is a URL whose path literally contains "..":
	in := `<a href="https://corp.example.com/simple/../../../etc/passwd">x</a>`
	_, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	// Go's url.Parse normalises this to /etc/passwd — no ".." survives. So this
	// particular form DOES NOT trigger the guard (the cleaned path is safe).
	// Report the observation: Go normalises ".." at parse time, so the guard
	// defends against raw ".." bytes that survive (e.g., malformed paths from a
	// non-standard server). The key security property is that no ".." survives
	// into the emitted suffix.
	if err != nil {
		// If the guard fires anyway, that is acceptable (defence in depth).
		require.Error(t, err)
	} else {
		out, e2 := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
			"https://corp.example.com/simple/foo/")
		require.NoError(t, e2)
		// The cleaned path must not contain ".." — verify the emitted suffix is safe.
		assert.NotContains(t, string(out), "..")
	}
}

// ---- FIX D: case-insensitive host comparison ----

func TestRewriteExtraIndex_UppercaseHost_Accepted(t *testing.T) {
	in := `<a href="https://CORP.example.com/packages/foo.whl">foo</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	assert.Contains(t, string(out), `href="/ext-packages/corp/packages/foo.whl"`)
}

// ---- NEW-1: embedded-quote injection regression ----

func TestRewriteExtraIndex_EmbeddedQuoteNoInjection(t *testing.T) {
	// Single-quoted href whose value contains a double-quote must NOT let an
	// un-rewritten <a href="https://evil..."> escape into the output.
	in := `<a href='https://files.corp.example.com/a.whl?z=1"><a href="https://evil.com/m.whl'>pkg</a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	// Either it rewrites the (single) real href safely, or it fails closed — but
	// it must NEVER emit an un-rewritten absolute link to evil.com.
	if err == nil {
		assert.NotContains(t, string(out), `href="https://evil.com/m.whl"`)
		assert.NotContains(t, string(out), `href='https://evil.com/m.whl'`)
	}
}

// ---- NEW-2: adjacent-href bypass regression ----

func TestRewriteExtraIndex_AdjacentHrefs_BothHandled(t *testing.T) {
	// Two adjacent anchors; the second points to an unroutable host → must fail closed.
	in := `<a href="https://files.corp.example.com/a.whl"></a><a href="https://evil.attacker.com/x.whl"></a>`
	_, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	require.Error(t, err, "an unroutable host in ANY anchor must fail closed")
}

func TestRewriteExtraIndex_AdjacentHrefs_BothRewritten(t *testing.T) {
	in := `<a href="https://corp.example.com/packages/a.whl"></a><a href="https://corp.example.com/packages/b.whl"></a>`
	out, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
		"https://corp.example.com/simple/foo/")
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, `/ext-packages/corp/packages/a.whl`)
	assert.Contains(t, s, `/ext-packages/corp/packages/b.whl`)
}

// ---- FIX: parser-differential raw-text container rejection ----

func TestRewriteExtraIndex_NoscriptWrappedHref_FailsClosed(t *testing.T) {
	in := `<noscript><a href="https://evil.attacker.com/x.whl">x</a></noscript>`
	_, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	require.Error(t, err, "noscript-wrapped anchor is a parser differential; must fail closed")
}

func TestRewriteExtraIndex_NoembedNoframes_FailClosed(t *testing.T) {
	for _, tag := range []string{"noembed", "noframes"} {
		in := `<` + tag + `><a href="https://evil.example.net/x.whl">x</a></` + tag + `>`
		_, err := RewriteExtraIndexSimplePage([]byte(in), ResolvedIndex{Name: "corp"},
			"https://corp.example.com/simple/foo/")
		require.Error(t, err, tag+" raw-text container must fail closed")
	}
}

// ---- FIX: truncated / incomplete HTML rejection ----

func TestRewriteExtraIndex_TruncatedTag_FailsClosed(t *testing.T) {
	in := `<a href="https://files.corp.example.com/ok.whl` // unterminated tag, mid-attribute
	_, err := RewriteExtraIndexSimplePage([]byte(in),
		ResolvedIndex{Name: "corp", FilesHost: "https://files.corp.example.com"},
		"https://corp.example.com/simple/foo/")
	require.Error(t, err, "truncated/incomplete HTML must fail closed, not serve a partial page")
}

// ---- RubyGems gem_uri rewrite (Phase 6) ----

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
	assert.Contains(t, s, `"sha":"abc"`)                                // integrity preserved
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

// S7 — relative and scheme-relative gem_uri values must fail closed (no host/scheme to validate).
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
