package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func newTestSessionStore(t *testing.T) *auth.SessionStore {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	s := auth.NewSessionStore(db, time.Hour)
	t.Cleanup(s.Stop)
	return s
}

func TestOIDCMiddleware_ValidSessionCookie_PassesThrough(t *testing.T) {
	store := newTestSessionStore(t)
	sid, err := store.Create(&auth.UserInfo{Subject: "user-123", Email: "alice@example.com", Name: "Alice"})
	require.NoError(t, err)

	mw := auth.NewOIDCMiddleware(store)

	var captured *auth.UserInfo
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = auth.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.AddCookie(&http.Cookie{Name: "shieldoo_session", Value: sid})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "user-123", captured.Subject)
	assert.Equal(t, "alice@example.com", captured.Email)
}

func TestOIDCMiddleware_NoCookie_Returns401(t *testing.T) {
	store := newTestSessionStore(t)
	mw := auth.NewOIDCMiddleware(store)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing or invalid session")
}

func TestOIDCMiddleware_UnknownSession_Returns401(t *testing.T) {
	store := newTestSessionStore(t)
	mw := auth.NewOIDCMiddleware(store)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.AddCookie(&http.Cookie{Name: "shieldoo_session", Value: "bogus-session-id"})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// An OIDC ID token presented on the Authorization header must NOT authenticate the
// admin API (token-type confusion fix); only the session cookie is accepted here.
func TestOIDCMiddleware_BearerToken_IsIgnored(t *testing.T) {
	store := newTestSessionStore(t)
	mw := auth.NewOIDCMiddleware(store)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for a bearer token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
	req.Header.Set("Authorization", "Bearer some.jwt.token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code, "ID token must not be accepted as an API bearer")
}

// Browser requests (Accept: text/html) without a session are redirected to login.
func TestOIDCMiddleware_BrowserNoSession_RedirectsToLogin(t *testing.T) {
	store := newTestSessionStore(t)
	mw := auth.NewOIDCMiddleware(store)
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/auth/login", rr.Header().Get("Location"))
}

func TestUserFromContext_ReturnsUser(t *testing.T) {
	user := &auth.UserInfo{Subject: "sub-1", Email: "test@example.com", Name: "Test User"}
	ctx := auth.ContextWithUser(context.Background(), user)

	got := auth.UserFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, "sub-1", got.Subject)
	assert.Equal(t, "test@example.com", got.Email)
}

func TestUserFromContext_NoUser_ReturnsNil(t *testing.T) {
	assert.Nil(t, auth.UserFromContext(context.Background()))
}
