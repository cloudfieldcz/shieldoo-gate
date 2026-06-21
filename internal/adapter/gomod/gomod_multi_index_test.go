package gomod_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/gomod"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func newMultiIndexGoMod(t *testing.T, defaultURL string, extras []config.UpstreamIndex) *gomod.GoModAdapter {
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
	return gomod.NewGoModAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: defaultURL, ExtraIndexes: extras})
}

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

// S6 — cross-host download redirect must NOT carry the per-index credential.
func TestGoModAdapter_DownloadRedirectToForeignHost_StripsAuth(t *testing.T) {
	var foreignAuth string
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PK\x03\x04dummy-zip"))
	}))
	t.Cleanup(foreign.Close)
	corp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_GO_CORP_TOK", "tok-secret")
	a := newMultiIndexGoMod(t, "https://proxy.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"github.com/mycompany/*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_GO_CORP_TOK"},
	}})
	req := httptest.NewRequest(http.MethodGet, "/github.com/mycompany/lib/@v/v1.0.0.zip", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Empty(t, foreignAuth, "Authorization must be stripped on cross-host redirect")
}
