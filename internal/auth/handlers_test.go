package auth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// stubIDP serves a minimal OIDC discovery document. issuer must equal the server URL.
func stubIDP(t *testing.T, withEndSession bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	doc := map[string]any{
		"issuer":                 srv.URL,
		"authorization_endpoint": srv.URL + "/auth",
		"token_endpoint":         srv.URL + "/token",
		"jwks_uri":               srv.URL + "/jwks",
	}
	if withEndSession {
		doc["end_session_endpoint"] = srv.URL + "/logout"
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	return srv
}

func newAuthHandlersForTest(t *testing.T, srvURL string) *auth.AuthHandlers {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	store := auth.NewSessionStore(db, time.Hour)
	t.Cleanup(store.Stop)

	h, err := auth.NewAuthHandlers(auth.AuthConfig{
		Enabled:               true,
		IssuerURL:             srvURL,
		ClientID:              "shieldoo-gate",
		RedirectURL:           "http://localhost:8080/auth/callback",
		PostLogoutRedirectURL: "http://localhost:8080",
		CookieInsecure:        true,
	}, store)
	require.NoError(t, err)
	return h
}

func TestNewAuthHandlers_ReadsEndSessionEndpoint(t *testing.T) {
	srv := stubIDP(t, true)
	h := newAuthHandlersForTest(t, srv.URL)
	assert.Equal(t, srv.URL+"/logout", h.EndSessionURL())
}

func TestNewAuthHandlers_NoEndSessionEndpoint(t *testing.T) {
	srv := stubIDP(t, false)
	h := newAuthHandlersForTest(t, srv.URL)
	assert.Equal(t, "", h.EndSessionURL())
}

// stubIDPEndSession serves discovery advertising the given end_session_endpoint verbatim
// (pass "" to omit it). issuer == server URL so discovery succeeds.
func stubIDPEndSession(t *testing.T, endSession string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	doc := map[string]any{
		"issuer":                 srv.URL,
		"authorization_endpoint": srv.URL + "/auth",
		"token_endpoint":         srv.URL + "/token",
		"jwks_uri":               srv.URL + "/jwks",
	}
	if endSession != "" {
		doc["end_session_endpoint"] = endSession
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	return srv
}

func newLogoutHandlers(t *testing.T, endSession string) (*auth.AuthHandlers, *auth.SessionStore) {
	t.Helper()
	srv := stubIDPEndSession(t, endSession)
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	store := auth.NewSessionStore(db, time.Hour)
	t.Cleanup(store.Stop)
	h, err := auth.NewAuthHandlers(auth.AuthConfig{
		Enabled:               true,
		IssuerURL:             srv.URL,
		ClientID:              "shieldoo-gate",
		RedirectURL:           "http://localhost:8080/auth/callback",
		PostLogoutRedirectURL: "http://localhost:8080",
		CookieInsecure:        true,
	}, store)
	require.NoError(t, err)
	return h, store
}

func TestHandleLogout_EndSessionConfigured_ReturnsLogoutURL(t *testing.T) {
	h, store := newLogoutHandlers(t, "https://idp.example.com/logout")
	sid, err := store.Create(&auth.UserInfo{Subject: "s", Email: "op@example.com"}, "raw.id.token")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "shieldoo_session", Value: sid})
	rr := httptest.NewRecorder()
	h.HandleLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var resp struct {
		Status    string `json:"status"`
		LogoutURL string `json:"logout_url"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "logged_out", resp.Status)

	u, err := url.Parse(resp.LogoutURL)
	require.NoError(t, err)
	assert.Equal(t, "idp.example.com", u.Host)
	q := u.Query()
	assert.Equal(t, "shieldoo-gate", q.Get("client_id"))
	assert.Equal(t, "http://localhost:8080", q.Get("post_logout_redirect_uri"))
	assert.Equal(t, "raw.id.token", q.Get("id_token_hint"))

	// session must be revoked
	_, ok := store.Validate(sid)
	assert.False(t, ok)
}

func TestHandleLogout_NoEndSession_ReturnsLoggedOut(t *testing.T) {
	h, store := newLogoutHandlers(t, "") // discovery advertises no end_session_endpoint
	sid, err := store.Create(&auth.UserInfo{Email: "op@example.com"}, "raw.id.token")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "shieldoo_session", Value: sid})
	rr := httptest.NewRecorder()
	h.HandleLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"status":"logged_out"}`, rr.Body.String())
}

func TestHandleLogout_NoStoredIDToken_OmitsHint(t *testing.T) {
	h, store := newLogoutHandlers(t, "https://idp.example.com/logout")
	sid, err := store.Create(&auth.UserInfo{Email: "op@example.com"}, "") // no id_token
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "shieldoo_session", Value: sid})
	rr := httptest.NewRecorder()
	h.HandleLogout(rr, req)

	var resp struct {
		LogoutURL string `json:"logout_url"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	u, _ := url.Parse(resp.LogoutURL)
	_, hasHint := u.Query()["id_token_hint"]
	assert.False(t, hasHint, "id_token_hint must be omitted when no token is stored")
}

func TestHandleLogout_NoCookie_NoOp(t *testing.T) {
	h, _ := newLogoutHandlers(t, "https://idp.example.com/logout")
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil) // no cookie
	rr := httptest.NewRecorder()
	h.HandleLogout(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code) // still succeeds, no panic
}

func TestHandleLogout_IgnoresRequestParams(t *testing.T) {
	h, store := newLogoutHandlers(t, "https://idp.example.com/logout")
	sid, err := store.Create(&auth.UserInfo{Email: "op@example.com"}, "raw.id.token")
	require.NoError(t, err)

	// Attacker-controlled query/body MUST NOT influence post_logout_redirect_uri.
	req := httptest.NewRequest(http.MethodPost, "/auth/logout?post_logout_redirect_uri=https://evil.example.com", nil)
	req.AddCookie(&http.Cookie{Name: "shieldoo_session", Value: sid})
	rr := httptest.NewRecorder()
	h.HandleLogout(rr, req)

	var resp struct {
		LogoutURL string `json:"logout_url"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	u, _ := url.Parse(resp.LogoutURL)
	assert.Equal(t, "http://localhost:8080", u.Query().Get("post_logout_redirect_uri"))
	assert.NotContains(t, resp.LogoutURL, "evil.example.com")
}

func TestHandleLogout_MalformedEndSession_DegradesAndNeverLogsIDToken(t *testing.T) {
	// A control char in the endpoint forces the url.Parse failure branch. Assert it degrades
	// to local-only logout (200, no logout_url, session still revoked) and never leaks the
	// id_token to the response or the logs.
	const secret = "raw.id.token.SECRET"
	h, store := newLogoutHandlers(t, "https://idp.example.com/logout\x7f")
	sid, err := store.Create(&auth.UserInfo{Email: "op@example.com"}, secret)
	require.NoError(t, err)

	var buf bytes.Buffer
	old := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = old })

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "shieldoo_session", Value: sid})
	rr := httptest.NewRecorder()
	h.HandleLogout(rr, req)

	require.Equal(t, http.StatusOK, rr.Code) // degrade, not 500 — local logout already done
	assert.JSONEq(t, `{"status":"logged_out"}`, rr.Body.String())
	assert.NotContains(t, buf.String(), secret, "logs must never contain the id_token")
	_, ok := store.Validate(sid)
	assert.False(t, ok, "session must be revoked even when the end-session URL is malformed")
}
