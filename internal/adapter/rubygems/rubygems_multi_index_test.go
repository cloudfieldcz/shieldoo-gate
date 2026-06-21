package rubygems_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/rubygems"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

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

func TestRubyGemsAdapter_ExtraIndexInfo_FansOut(t *testing.T) {
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info/mycompany-gem" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("---\n1.0.0 |checksum:abc\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(corp.Close)
	a := newMultiIndexRubyGems(t, "https://rubygems.invalid",
		[]config.UpstreamIndex{{Name: "private", URL: corp.URL, Packages: []string{"mycompany-*"}}})
	req := httptest.NewRequest(http.MethodGet, "/info/mycompany-gem", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "1.0.0 |checksum:abc")
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
