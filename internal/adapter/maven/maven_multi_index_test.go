package maven_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
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
