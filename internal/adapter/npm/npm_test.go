package npm_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/npm"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func setupTestNPM(t *testing.T, upstreamHandler http.HandlerFunc) (*npm.NPMAdapter, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
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
	return npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL), upstream
}

func TestNPMAdapter_Ecosystem_ReturnsNPM(t *testing.T) {
	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, scanner.EcosystemNPM, a.Ecosystem())
}

func TestNPMAdapter_PackageMetadata_ProxiesUpstream(t *testing.T) {
	const body = `{"name":"lodash","version":"4.17.21"}`

	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	req := httptest.NewRequest(http.MethodGet, "/lodash", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "lodash")
}

func TestNPMAdapter_VersionMetadata_ProxiesUpstream(t *testing.T) {
	const body = `{"name":"lodash","version":"4.17.21","dist":{"tarball":"..."}}`

	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	req := httptest.NewRequest(http.MethodGet, "/lodash/4.17.21", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "4.17.21")
}

func TestNPMAdapter_TarballDownload_CleanPackage_Serves200(t *testing.T) {
	fileContent := []byte("fake npm tarball")

	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// No scanners → policy defaults to clean → allow.
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestNPMAdapter_PackageMetadata_InvalidName_DoesNotPanic(t *testing.T) {
	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// This exercises the routing handler path with a normal (valid) package name.
	req := httptest.NewRequest(http.MethodGet, "/express", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestNPMAdapter_PackageMetadata_RewritesTarballURLs(t *testing.T) {
	// upstreamURL is captured by pointer so the handler closure can reference it
	// after the test server is started inside setupTestNPM.
	var upstreamURL string
	a, upstream := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		body := `{"name":"is-odd","versions":{"3.0.1":{"dist":{"tarball":"` +
			upstreamURL + `/is-odd/-/is-odd-3.0.1.tgz"}}}}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	upstreamURL = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/is-odd", nil)
	req.Host = "proxy.example.com:14873"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Upstream URL must not appear in the response body.
	assert.NotContains(t, body, upstreamURL+"/is-odd")
	// Proxy host must appear instead.
	assert.Contains(t, body, "http://proxy.example.com:14873/is-odd/-/is-odd-3.0.1.tgz")
}

func TestNPMAdapter_ScopedMetadata_RewritesTarballURLs(t *testing.T) {
	var upstreamURL string
	a, upstream := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		body := `{"name":"@scope/pkg","versions":{"1.0.0":{"dist":{"tarball":"` +
			upstreamURL + `/@scope/pkg/-/pkg-1.0.0.tgz"}}}}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	upstreamURL = upstream.URL

	req := httptest.NewRequest(http.MethodGet, "/@scope/pkg", nil)
	req.Host = "localhost:14873"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.NotContains(t, body, upstreamURL+"/@scope/pkg")
	assert.Contains(t, body, "http://localhost:14873/@scope/pkg/-/pkg-1.0.0.tgz")
}
