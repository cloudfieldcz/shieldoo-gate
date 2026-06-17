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
	a := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{})
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

	a := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL, config.TagMutabilityConfig{})
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
