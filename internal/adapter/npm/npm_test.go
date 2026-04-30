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
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
)

// setupTestNPMWithTyposquat builds an NPM adapter wired with the real builtin
// typosquat scanner, so that PreScanTyposquat behaves like in production.
func setupTestNPMWithTyposquat(t *testing.T, upstreamHandler http.HandlerFunc) (*npm.NPMAdapter, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	tsq, err := builtin.NewTyposquatScanner(db, config.TyposquatConfig{
		Enabled:          true,
		MaxEditDistance:  2,
		TopPackagesCount: 5000,
	})
	require.NoError(t, err)

	scanEngine := scanner.NewEngine([]scanner.Scanner{tsq}, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)
	return npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{}), upstream
}

func setupTestNPM(t *testing.T, upstreamHandler http.HandlerFunc) (*npm.NPMAdapter, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)
	return npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{}), upstream
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

func TestNPMAdapter_ScopedMetadata_PercentEncodedSlash_RoutesToScopedHandler(t *testing.T) {
	var gotPath string
	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"@alloc/quick-lru"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/@alloc%2Fquick-lru", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/@alloc/quick-lru", gotPath, "upstream must receive decoded scoped path")
}

func TestNPMAdapter_ScopedMetadata_LowercasePercentEncodedSlash_RoutesToScopedHandler(t *testing.T) {
	var gotPath string
	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"@alloc/quick-lru"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/@alloc%2fquick-lru", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/@alloc/quick-lru", gotPath, "upstream must receive decoded scoped path")
}

func TestNPMAdapter_ScopedTarball_PercentEncodedSlash_Serves200(t *testing.T) {
	var gotPath string
	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake tarball"))
	})

	req := httptest.NewRequest(http.MethodGet, "/@alloc%2Fquick-lru/-/quick-lru-5.2.0.tgz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/@alloc/quick-lru/-/quick-lru-5.2.0.tgz", gotPath, "upstream must receive decoded scoped tarball path")
}

func TestNPMAdapter_ScopedVersion_PercentEncodedSlash_ProxiesUpstream(t *testing.T) {
	var gotPath string
	a, _ := setupTestNPM(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"@alloc/quick-lru","version":"5.2.0"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/@alloc%2Fquick-lru/5.2.0", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/@alloc/quick-lru/5.2.0", gotPath, "upstream must receive decoded scoped version path")
}

// TestNPMAdapter_VitestNotBlocked_RegressionForTyposquatFalsePositive verifies
// that a request for the legitimate package "vitest" is NOT blocked at the
// pre-scan stage by the typosquat scanner (regression: vitest is within
// edit distance 2 of "vite"). With vitest in the popular_packages seed,
// Strategy 1 (exact-match) must short-circuit the edit-distance check.
func TestNPMAdapter_VitestNotBlocked_RegressionForTyposquatFalsePositive(t *testing.T) {
	const body = `{"name":"vitest","versions":{"1.0.0":{}}}`
	upstreamHit := false

	a, _ := setupTestNPMWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	req := httptest.NewRequest(http.MethodGet, "/vitest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code,
		"vitest must not be blocked by typosquat pre-scan")
	assert.True(t, upstreamHit,
		"request must reach upstream, not be short-circuited at pre-scan")
	assert.NotContains(t, w.Body.String(), "typosquatting detected")
}

// TestNPMAdapter_TyposquatStillBlocksGenuineSquats is the positive control:
// a genuine typosquat (close to a popular package but not itself popular) MUST
// still be blocked, ensuring the seed expansion did not disable the scanner.
func TestNPMAdapter_TyposquatStillBlocksGenuineSquats(t *testing.T) {
	upstreamHit := false

	a, _ := setupTestNPMWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	// "lodahs" is ed=2 from "lodash" and not a real package.
	req := httptest.NewRequest(http.MethodGet, "/lodahs", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"genuine typosquat must still be blocked")
	assert.False(t, upstreamHit,
		"genuine typosquat must be blocked before reaching upstream")
	assert.Contains(t, w.Body.String(), "typosquatting detected")
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
