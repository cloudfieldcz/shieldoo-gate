package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
)

func newProjectSvc(t *testing.T, cfg project.Config) (*config.GateDB, project.Service) {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	svc, err := project.NewService(cfg, db)
	require.NoError(t, err)
	t.Cleanup(svc.Stop)
	return db, svc
}

func TestMiddleware_ProjectFromUsername_LazyCreate(t *testing.T) {
	db, svc := newProjectSvc(t, project.Config{Mode: project.ModeLazy})

	// Create a PAT.
	plaintext := "sgw_test_pat"
	_, err := db.CreateAPIKey(sha256Hex(plaintext), "pat-name", "dev@example.com")
	require.NoError(t, err)

	mw := NewAPIKeyMiddleware(db, "").WithProjectService(svc)
	defer mw.Stop()

	var captured *project.Project
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = project.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("team-alpha", plaintext))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "team-alpha", captured.Label)
	assert.Equal(t, "lazy", captured.CreatedVia)
}

func TestMiddleware_EmptyUsername_MapsToDefaultProject(t *testing.T) {
	db, svc := newProjectSvc(t, project.Config{Mode: project.ModeLazy})
	plaintext := "sgw_test_pat"
	_, err := db.CreateAPIKey(sha256Hex(plaintext), "pat", "dev@example.com")
	require.NoError(t, err)

	mw := NewAPIKeyMiddleware(db, "").WithProjectService(svc)
	defer mw.Stop()

	var captured *project.Project
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = project.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("", plaintext))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "default", captured.Label)
}

func TestMiddleware_StrictMode_UnknownLabel_Returns403(t *testing.T) {
	db, svc := newProjectSvc(t, project.Config{Mode: project.ModeStrict})
	plaintext := "sgw_test_pat"
	_, err := db.CreateAPIKey(sha256Hex(plaintext), "pat", "dev@example.com")
	require.NoError(t, err)

	mw := NewAPIKeyMiddleware(db, "").WithProjectService(svc)
	defer mw.Stop()

	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("never-created", plaintext))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "project_not_found")
}

func TestMiddleware_InvalidLabel_Returns400(t *testing.T) {
	db, svc := newProjectSvc(t, project.Config{Mode: project.ModeLazy})
	plaintext := "sgw_test_pat"
	_, err := db.CreateAPIKey(sha256Hex(plaintext), "pat", "dev@example.com")
	require.NoError(t, err)

	mw := NewAPIKeyMiddleware(db, "").WithProjectService(svc)
	defer mw.Stop()

	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("bad@chars!!", plaintext))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_project_label")
}

func TestMiddleware_UsernameIsNotKeyOwnerEmail(t *testing.T) {
	// Regression: ensure Basic auth username (NOT key.OwnerEmail) drives project label.
	db, svc := newProjectSvc(t, project.Config{Mode: project.ModeLazy})
	plaintext := "sgw_test_pat"
	_, err := db.CreateAPIKey(sha256Hex(plaintext), "pat", "owner@example.com")
	require.NoError(t, err)

	mw := NewAPIKeyMiddleware(db, "").WithProjectService(svc)
	defer mw.Stop()

	var captured *project.Project
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = project.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("payments-service", plaintext))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, captured)
	// Critical: label comes from Basic auth username, not from owner email.
	assert.Equal(t, "payments-service", captured.Label)
	assert.NotEqual(t, "owner@example.com", captured.Label)
}

func TestMiddleware_GlobalToken_ProjectResolution(t *testing.T) {
	db, svc := newProjectSvc(t, project.Config{Mode: project.ModeLazy})
	mw := NewAPIKeyMiddleware(db, "gt-secret").WithProjectService(svc)
	defer mw.Stop()

	var captured *project.Project
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = project.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", basicAuthHeader("ci-pipeline", "gt-secret"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "ci-pipeline", captured.Label)
}
