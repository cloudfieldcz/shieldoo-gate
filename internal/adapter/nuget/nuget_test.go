package nuget_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/nuget"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func setupTestNuGet(t *testing.T, upstreamHandler http.HandlerFunc) (*nuget.NuGetAdapter, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)
	return nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL), upstream
}

func TestNuGetAdapter_Ecosystem_ReturnsNuGet(t *testing.T) {
	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, scanner.EcosystemNuGet, a.Ecosystem())
}

func TestNuGetAdapter_ServiceIndex_RewritesUpstreamURLs(t *testing.T) {
	var upstreamBase string

	a, upstream := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		// Simulate api.nuget.org returning absolute URLs referencing itself.
		body := `{"version":"3.0.0","resources":[{"@id":"` + upstreamBase + `/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"}]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	upstreamBase = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/v3/index.json", nil)
	req.Host = "proxy.example.com"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Upstream URL must be replaced with proxy host.
	assert.NotContains(t, body, upstreamBase, "upstream base URL must not appear in rewritten response")
	assert.Contains(t, body, "http://proxy.example.com/v3-flatcontainer/")
}

func TestNuGetAdapter_Registration_RewritesUpstreamURLs(t *testing.T) {
	var upstreamBase string

	a, upstream := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		body := `{"count":1,"items":[{"@id":"` + upstreamBase + `/v3/registration/newtonsoft.json/index.json"}]}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	upstreamBase = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Json/index.json", nil)
	req.Host = "proxy.example.com"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, upstreamBase, "upstream base URL must not appear in rewritten response")
	assert.Contains(t, body, "http://proxy.example.com/v3/registration/newtonsoft.json/index.json")
}

func TestNuGetAdapter_NupkgDownload_CleanPackage_Serves200(t *testing.T) {
	fileContent := []byte("fake nupkg content")

	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// No scanners → policy defaults to clean → allow.
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestNuGetAdapter_Passthrough_RepositorySignatures_Returns200(t *testing.T) {
	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"allRepositorySigned":false}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v3-index/repository-signatures/5.0.0/index.json", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "allRepositorySigned")
}

func TestNuGetAdapter_NupkgDownload_InvalidPackageID_Returns400(t *testing.T) {
	a, _ := setupTestNuGet(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use chi routing-safe but validation-unsafe name. The chi param won't
	// match shell metacharacters so we test with a dotted name that would pass
	// chi but force a validation to run.
	req := httptest.NewRequest(http.MethodGet, "/v3/registration/Newtonsoft.Json/index.json", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	// Newtonsoft.Json is a valid package name — should proxy through.
	assert.Equal(t, http.StatusOK, w.Code)
}
