package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
)

// newScopeTestServer builds a Server whose admin API is gated by the PAT-Bearer
// auth chain (no OIDC) with scope enforcement active, so a token's scopes drive
// authorization — mirroring a secured deployment (auth/proxy_auth enabled).
func newScopeTestServer(t *testing.T) (http.Handler, func(scopes string) string) {
	t.Helper()
	s, db := setupTestServer(t)
	pat := auth.NewPATBearerMiddleware(db, "", nil)
	s.SetAdminAuthChain(auth.NewAdminAuthChain(pat, nil), pat)
	s.SetAdminScopeEnforcement(true)
	handler := s.Routes()

	// mintToken inserts a PAT with the given comma-separated scopes and returns
	// the plaintext bearer token.
	mintToken := func(scopes string) string {
		plaintext := "sgw_test_" + scopes
		hash := sha256Hex(plaintext)
		_, err := db.CreateAPIKeyWithScopes(hash, "tok-"+scopes, "op@example.com", scopes)
		require.NoError(t, err)
		return plaintext
	}
	return handler, mintToken
}

func doBearer(handler http.Handler, method, path, token string) int {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestAdminAPI_ProxyFetchToken_ForbiddenOnEverything(t *testing.T) {
	handler, mint := newScopeTestServer(t)
	tok := mint("proxy:fetch")
	// Regression test for the reported privilege-escalation vuln: a proxy:fetch
	// token must NOT reach any admin route, read or write.
	assert.Equal(t, http.StatusForbidden, doBearer(handler, "GET", "/api/v1/artifacts", tok),
		"proxy:fetch must be forbidden on admin GET")
	assert.Equal(t, http.StatusForbidden, doBearer(handler, "POST", "/api/v1/artifacts/x/quarantine", tok),
		"proxy:fetch must be forbidden on admin mutation")
}

func TestAdminAPI_ReadToken_AllowsGetForbidsMutation(t *testing.T) {
	handler, mint := newScopeTestServer(t)
	tok := mint("admin:read")
	assert.NotEqual(t, http.StatusForbidden, doBearer(handler, "GET", "/api/v1/artifacts", tok),
		"admin:read should pass the GET authorization gate")
	assert.Equal(t, http.StatusForbidden, doBearer(handler, "POST", "/api/v1/artifacts/x/quarantine", tok),
		"admin:read must be forbidden on a mutation")
}

func TestAdminAPI_WriteToken_AllowsMutationAndRead(t *testing.T) {
	handler, mint := newScopeTestServer(t)
	tok := mint("admin:write")
	assert.NotEqual(t, http.StatusForbidden, doBearer(handler, "GET", "/api/v1/artifacts", tok),
		"admin:write should imply admin:read on GET")
	assert.NotEqual(t, http.StatusForbidden, doBearer(handler, "POST", "/api/v1/artifacts/x/quarantine", tok),
		"admin:write should pass the mutation authorization gate")
}

// TestAdminAPI_NoAuthMode_NotScopeGated reproduces the dev/no-auth regression:
// main.go wires the admin auth chain unconditionally ("always-on"), so adminChain
// is non-nil even when neither auth nor proxy_auth is enabled. Scope enforcement
// must NOT activate in that mode, or an unauthenticated dev/CI request to the
// admin API gets a spurious 403 (which broke the no-auth e2e run).
func TestAdminAPI_NoAuthMode_NotScopeGated(t *testing.T) {
	s, db := setupTestServer(t)
	pat := auth.NewPATBearerMiddleware(db, "", nil)
	s.SetAdminAuthChain(auth.NewAdminAuthChain(pat, nil), pat)
	// Scope enforcement intentionally left OFF (no auth / no proxy_auth).
	handler := s.Routes()

	req := httptest.NewRequest("GET", "/api/v1/artifacts", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"no-auth mode must leave the admin API open (no scope gate)")
}

func TestHealth_NoCredentials_Unaffected(t *testing.T) {
	handler, _ := newScopeTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code, "health must not require a scope")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code, "health must stay unauthenticated")
}
