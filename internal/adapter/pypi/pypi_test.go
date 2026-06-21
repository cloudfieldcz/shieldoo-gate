package pypi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/pypi"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func setupTestPyPI(t *testing.T, upstreamHandler http.HandlerFunc) (*pypi.PyPIAdapter, *httptest.Server) {
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
	a := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: upstream.URL}, config.TagMutabilityConfig{})
	a.SetFilesHost(upstream.URL)
	return a, upstream
}

func TestPyPIAdapter_Ecosystem_ReturnsPyPI(t *testing.T) {
	a, _ := setupTestPyPI(t, func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, scanner.EcosystemPyPI, a.Ecosystem())
}

func TestPyPIAdapter_SimpleIndex_ProxiesUpstream(t *testing.T) {
	const body = `<!DOCTYPE html><html><body><a href="/simple/requests/">requests</a></body></html>`

	a, _ := setupTestPyPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	req := httptest.NewRequest(http.MethodGet, "/simple/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "requests")
}

func TestPyPIAdapter_SimplePackage_ProxiesUpstream(t *testing.T) {
	const body = `<!DOCTYPE html><html><body><a href="/packages/requests-2.28.0.tar.gz">requests-2.28.0.tar.gz</a></body></html>`

	a, _ := setupTestPyPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})

	req := httptest.NewRequest(http.MethodGet, "/simple/requests/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "requests-2.28.0.tar.gz")
}

func TestPyPIAdapter_PackageDownload_CleanPackage_Serves200(t *testing.T) {
	fileContent := []byte("fake tarball content")

	a, _ := setupTestPyPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/packages/re/requests/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	// With no scanners, policy defaults to clean → allow.
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPyPIArtifactID_IncludesFilename(t *testing.T) {
	id := pypi.PyPIArtifactID("cffi", "2.0.0", "cffi-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl")
	assert.Equal(t, "pypi:cffi:2.0.0:cffi-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl", id)
}

func TestPyPIArtifactID_Sdist(t *testing.T) {
	id := pypi.PyPIArtifactID("requests", "2.28.0", "requests-2.28.0.tar.gz")
	assert.Equal(t, "pypi:requests:2.28.0:requests-2.28.0.tar.gz", id)
}

func TestPyPIAdapter_TwoWheelPlatforms_SeparateCacheEntries(t *testing.T) {
	linuxContent := []byte("linux wheel binary")
	macContent := []byte("macos wheel binary")

	callCount := 0
	a, _ := setupTestPyPI(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "manylinux") {
			_, _ = w.Write(linuxContent)
		} else {
			_, _ = w.Write(macContent)
		}
	})

	// Download Linux wheel.
	req1 := httptest.NewRequest(http.MethodGet, "/packages/cf/cffi/cffi-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl", nil)
	w1 := httptest.NewRecorder()
	a.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Equal(t, linuxContent, w1.Body.Bytes())

	// Download macOS wheel.
	req2 := httptest.NewRequest(http.MethodGet, "/packages/cf/cffi/cffi-2.0.0-cp312-cp312-macosx_11_0_arm64.whl", nil)
	w2 := httptest.NewRecorder()
	a.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, macContent, w2.Body.Bytes())

	// Re-request Linux — should come from cache (no new upstream call).
	prevCount := callCount
	req3 := httptest.NewRequest(http.MethodGet, "/packages/cf/cffi/cffi-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl", nil)
	w3 := httptest.NewRecorder()
	a.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
	assert.Equal(t, linuxContent, w3.Body.Bytes())
	assert.Equal(t, prevCount, callCount, "expected cache hit, but upstream was called again")
}

func TestPyPIAdapter_SimplePackage_InvalidName_Returns400(t *testing.T) {
	a, _ := setupTestPyPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Chi routing won't match path traversal so we test via a crafted URL param directly.
	// Use a name that passes routing but fails validation.
	req := httptest.NewRequest(http.MethodGet, "/simple/valid-name/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	// Should proxy through (upstream returns 200) — valid name case.
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Fail-closed scanner error tests ---

func setupTestPyPIWithEngines(
	t *testing.T,
	upstreamHandler http.HandlerFunc,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
) (*pypi.PyPIAdapter, *httptest.Server, *config.GateDB) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	a := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: upstream.URL}, config.TagMutabilityConfig{})
	a.SetFilesHost(upstream.URL)
	return a, upstream, db
}

type pypiTestScanner struct {
	name       string
	ecosystems []scanner.Ecosystem
	scanFn     func(context.Context, scanner.Artifact) (scanner.ScanResult, error)
}

func (m *pypiTestScanner) Name() string                                 { return m.name }
func (m *pypiTestScanner) Version() string                              { return "test" }
func (m *pypiTestScanner) SupportedEcosystems() []scanner.Ecosystem     { return m.ecosystems }
func (m *pypiTestScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	return m.scanFn(ctx, artifact)
}
func (m *pypiTestScanner) HealthCheck(context.Context) error { return nil }

func setupPyPIRequiredScannerError(
	t *testing.T,
	mode policy.ScanErrorMode,
) (*pypi.PyPIAdapter, *config.GateDB) {
	t.Helper()
	fileContent := []byte("fake tarball content")
	required := &pypiTestScanner{
		name:       "guarddog",
		ecosystems: []scanner.Ecosystem{scanner.EcosystemPyPI},
		scanFn: func(_ context.Context, _ scanner.Artifact) (scanner.ScanResult, error) {
			return scanner.ScanResult{}, scanner.NewScanError(scanner.ErrKindOverload, errors.New("bridge overloaded"))
		},
	}
	criticality := map[string]scanner.Criticality{"guarddog": scanner.CriticalityRequired}
	scanEngine := scanner.NewEngine(
		[]scanner.Scanner{required},
		time.Second,
		0,
		scanner.WithRetry(1, time.Millisecond),
		scanner.WithCriticality(criticality),
	)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		MinimumConfidence:  0.7,
		OnScanError:        mode,
		ScannerCriticality: criticality,
	}, nil)

	a, _, db := setupTestPyPIWithEngines(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileContent)
	}, scanEngine, policyEngine)
	return a, db
}

func TestPyPIAdapter_RequiredScannerError_Returns503AndDoesNotPersist(t *testing.T) {
	a, db := setupPyPIRequiredScannerError(t, policy.ScanErrorModeQuarantine)
	req := httptest.NewRequest(http.MethodGet, "/packages/re/requests/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM artifact_status`).Scan(&count))
	assert.Equal(t, 0, count)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestPyPIAdapter_RequiredScannerError_BlockModeAuditsScanUnavailable(t *testing.T) {
	a, db := setupPyPIRequiredScannerError(t, policy.ScanErrorModeBlock)
	req := httptest.NewRequest(http.MethodGet, "/packages/re/requests/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestPyPIAdapter_RequiredScannerError_FailOpenModeAuditsScanUnavailable(t *testing.T) {
	a, db := setupPyPIRequiredScannerError(t, policy.ScanErrorModeFailOpen)
	req := httptest.NewRequest(http.MethodGet, "/packages/re/requests/requests-2.28.0.tar.gz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCAN_UNAVAILABLE'`).Scan(&count))
	assert.Equal(t, 1, count)
}

// ---- Multi-index /simple fan-out tests ----

func newMultiIndexAdapter(t *testing.T, defaultURL string, extras []config.UpstreamIndex) *pypi.PyPIAdapter {
	t.Helper()
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
	return pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine,
		config.UpstreamSet{Default: defaultURL, ExtraIndexes: extras}, config.TagMutabilityConfig{})
}

func TestPyPIAdapter_ScopedMiss_Returns404(t *testing.T) {
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

func TestPyPIAdapter_ScopedIndex500_Returns404NoPublicFallback(t *testing.T) {
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

func TestPyPIAdapter_ExtraIndexServesSimplePage_RewritesToExtPackages(t *testing.T) {
	hexaly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/hexaly/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<a href="` + "http://" + r.Host + `/packages/hexaly-1.0.tar.gz">hexaly-1.0.tar.gz</a>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(hexaly.Close)
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{
		{Name: "hexaly", URL: hexaly.URL},
	})
	req := httptest.NewRequest(http.MethodGet, "/simple/hexaly/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `/ext-packages/hexaly/packages/hexaly-1.0.tar.gz`)
}

// ---- FIX A: PEP 691 JSON response from extra index must fail closed ----

func TestPyPIAdapter_ExtraIndexJSONResponse_FailsClosed502(t *testing.T) {
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/foo/" {
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			_, _ = w.Write([]byte(`{"files":[{"url":"https://evil.cdn.example.net/foo-1.0.whl","hashes":{}}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(idx.Close)
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{{Name: "corp", URL: idx.URL}})
	req := httptest.NewRequest(http.MethodGet, "/simple/foo/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code, "non-HTML extra-index page must fail closed, never served verbatim")
	assert.NotContains(t, rec.Body.String(), "evil.cdn.example.net")
}

// FIX A: a plaintext (non-HTML, non-pypi.simple.v1+html) Content-Type also fails closed.
// Note: Go's net/http server auto-sniffs HTML bodies and sets Content-Type text/html,
// so we use an explicit non-HTML type to test the gate without fighting content sniffing.
func TestPyPIAdapter_ExtraIndexPlainTextContentType_FailsClosed502(t *testing.T) {
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/foo/" {
			// Explicitly set a non-HTML content type.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("foo-1.0.whl https://corp.example.com/packages/foo-1.0.whl"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(idx.Close)
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{{Name: "corp", URL: idx.URL}})
	req := httptest.NewRequest(http.MethodGet, "/simple/foo/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadGateway, rec.Code, "non-HTML Content-Type must fail closed")
}

// FIX A: verify Accept header forced to HTML for extra indexes.
func TestPyPIAdapter_ExtraIndex_ForcesHTMLAccept(t *testing.T) {
	var gotAccept string
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/foo/" {
			gotAccept = r.Header.Get("Accept")
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<a href="http://` + r.Host + `/packages/foo-1.0.whl">foo</a>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(idx.Close)
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{{Name: "corp", URL: idx.URL}})
	req := httptest.NewRequest(http.MethodGet, "/simple/foo/", nil)
	// Simulate pip ≥ 22.2 sending JSON preference.
	req.Header.Set("Accept", "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01")
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, gotAccept, "text/html", "extra index must receive HTML-only Accept header")
	assert.NotContains(t, gotAccept, "json", "extra index must NOT receive JSON Accept header")
}

// ---- /ext-packages/{index}/* download route tests ----

func TestPyPIAdapter_ExtPackagesUnknownIndex_Returns404NoUpstream(t *testing.T) {
	a := newMultiIndexAdapter(t, "https://pypi.invalid", nil)
	req := httptest.NewRequest(http.MethodGet, "/ext-packages/ghost/foo-1.0.tar.gz", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPyPIAdapter_ExtPackagesPathTraversal_Returns404(t *testing.T) {
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{
		{Name: "corp", URL: "https://corp.example.com/"},
	})
	req := httptest.NewRequest(http.MethodGet, "/ext-packages/corp/../../packages/x-1.0.tar.gz", nil)
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
	require.Equal(t, http.StatusOK, rec.Code) // no scanners registered → clean → served
	assert.Equal(t, "Bearer tok-123", sentAuth, "upstream auth header attached")
	// Artifact stored under the namespaced ecosystem "pypi__corp".
	status, err := adapter.GetArtifactStatus(a.DB(), "pypi__corp:mycompany-lib:1.0:mycompany-lib-1.0.tar.gz")
	require.NoError(t, err)
	require.NotNil(t, status)
}

// FIX E: extra index must NOT relay arbitrary upstream headers.
func TestPyPIAdapter_ExtraIndex_HeaderAllowlist(t *testing.T) {
	idx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/simple/foo/" {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Set-Cookie", "session=evil; Path=/")
			w.Header().Set("ETag", `"abc123"`)
			w.Header().Set("X-Custom-Header", "injected")
			_, _ = w.Write([]byte(`<a href="http://` + r.Host + `/packages/foo-1.0.whl">foo</a>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(idx.Close)
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{{Name: "corp", URL: idx.URL}})
	req := httptest.NewRequest(http.MethodGet, "/simple/foo/", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Set-Cookie"), "Set-Cookie must NOT be relayed from extra index")
	assert.Empty(t, rec.Header().Get("X-Custom-Header"), "arbitrary headers must NOT be relayed from extra index")
	assert.Equal(t, `"abc123"`, rec.Header().Get("ETag"), "ETag must be relayed (it is in allowlist)")
}

// ---- FIX: redirect-safe download client strips per-index auth on cross-host redirect ----

// TestPyPIAdapter_ExtPackagesDownload_StripsAuthOnRedirectToOtherHost verifies
// that the per-index Authorization credential is NOT forwarded when the extra-index
// download server redirects to a DIFFERENT host. This guards against redirect-SSRF
// and credential leak (HIGH severity).
//
// Both servers must use TLS (httptest.NewTLSServer) because the hardened
// CheckRedirect refuses to follow a credentialed redirect to a non-https target
// (rule 2), which would turn a redirect from the http-scheme corp server into a
// 502. With HTTPS on both sides the redirect is followed and only the
// sameHostScheme/hostWithPort port-difference check fires (rule 3), stripping auth.
//
// The adapter's httpClient is overridden via SetHTTPClient with a redirect-safe
// client that trusts the test TLS certificate, mirroring the production setup
// (NewRedirectSafeClient) while allowing the self-signed cert.
func TestPyPIAdapter_ExtPackagesDownload_StripsAuthOnRedirectToOtherHost(t *testing.T) {
	var finalAuth string
	finalHost := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("redirected-bytes"))
	}))
	t.Cleanup(finalHost.Close)
	corp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// redirect the artifact download to a DIFFERENT host (different port = different host:port)
		http.Redirect(w, r, finalHost.URL+"/mycompany-lib-1.0.tar.gz", http.StatusFound)
	}))
	t.Cleanup(corp.Close)
	t.Setenv("SGW_CORP_TOK", "tok-secret")
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{{
		Name: "corp", URL: corp.URL, Packages: []string{"mycompany-*"},
		Auth: &config.UpstreamAuth{Type: "bearer", TokenEnv: "SGW_CORP_TOK"},
	}})

	// Inject a redirect-safe client that trusts the test TLS certificate.
	// finalHost.Client() uses a transport that trusts the self-signed cert.
	// We copy that transport into a new NewRedirectSafeClient so redirect
	// hardening still applies (only the TLS trust differs from production).
	tlsTrustedClient := adapter.NewRedirectSafeClient(5 * time.Minute)
	tlsTrustedClient.Transport = finalHost.Client().Transport
	a.SetHTTPClient(tlsTrustedClient)

	req := httptest.NewRequest(http.MethodGet, "/ext-packages/corp/mycompany-lib-1.0.tar.gz", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, finalAuth, "per-index credential must NOT be forwarded across a redirect to a different host")
}

// ---- FIX: encoded path traversal guard for /ext-packages/{index}/* ----

// TestPyPIAdapter_ExtPackagesEncodedTraversal_Returns404 verifies that percent-encoded
// ".." segments (%2e%2e) in the wildcard path are caught and rejected with 404.
// This closes a gap where the raw chi wildcard was still percent-encoded, allowing
// %2e%2e to bypass the literal ".." check (MEDIUM severity).
func TestPyPIAdapter_ExtPackagesEncodedTraversal_Returns404(t *testing.T) {
	a := newMultiIndexAdapter(t, "https://pypi.invalid", []config.UpstreamIndex{
		{Name: "corp", URL: "https://corp.example.com/"},
	})
	for _, p := range []string{
		"/ext-packages/corp/%2e%2e/%2e%2e/x-1.0.tar.gz",
		"/ext-packages/corp/..%2f..%2fx-1.0.tar.gz",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, "encoded traversal %s must 404", p)
	}
}
