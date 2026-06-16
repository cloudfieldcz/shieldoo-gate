package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName = "shieldoo_session"
	stateCookieName   = "shieldoo_oauth_state"
	pkceCodeCookie    = "shieldoo_pkce_verifier"
	nonceCookieName   = "shieldoo_oauth_nonce"
)

// AuthConfig holds OIDC configuration for the auth handlers.
type AuthConfig struct {
	Enabled         bool
	IssuerURL       string
	ClientID        string
	ClientSecretEnv string
	RedirectURL     string
	Scopes          []string
	// CookieInsecure, when true, drops the Secure attribute from auth cookies. It is
	// an explicit opt-out for local HTTP development ONLY. Default false → cookies are
	// always Secure, so the session cookie is never sent over cleartext (which would
	// expose it behind a TLS-terminating proxy configured with an http redirect URL).
	CookieInsecure bool
}

// AuthHandlers implements the OIDC Authorization Code flow with PKCE and issues
// opaque server-side sessions.
type AuthHandlers struct {
	oauth2Cfg    *oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	cfg          AuthConfig
	store        *SessionStore
	secureCookie bool
}

// NewAuthHandlers creates auth handlers by performing OIDC discovery against
// the configured issuer URL. The store persists sessions server-side.
func NewAuthHandlers(cfg AuthConfig, store *SessionStore) (*AuthHandlers, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(oidc.InsecureIssuerURLContext(ctx, cfg.IssuerURL), cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: discovering OIDC provider at %s: %w", cfg.IssuerURL, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	clientSecret := ""
	if cfg.ClientSecretEnv != "" {
		clientSecret = os.Getenv(cfg.ClientSecretEnv)
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &AuthHandlers{
		oauth2Cfg:    oauth2Cfg,
		provider:     provider,
		verifier:     verifier,
		cfg:          cfg,
		store:        store,
		secureCookie: !cfg.CookieInsecure,
	}, nil
}

// authCookie builds a hardened cookie with the handler's Secure setting.
func (h *AuthHandlers) authCookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
	}
}

// HandleLogin redirects the user to the OIDC provider's authorization endpoint.
// It generates state (CSRF), a PKCE verifier, and a nonce (binds the ID token to
// this authentication request), each stored in a short-lived httpOnly cookie.
func (h *AuthHandlers) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(32)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}
	codeVerifier, err := randomString(64)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to generate PKCE verifier")
		return
	}
	nonce, err := randomString(32)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to generate nonce")
		return
	}

	// SameSite=Lax so these survive the cross-site redirect back from the IdP.
	http.SetCookie(w, h.authCookie(stateCookieName, state, "/auth", 300))
	http.SetCookie(w, h.authCookie(pkceCodeCookie, codeVerifier, "/auth", 300))
	http.SetCookie(w, h.authCookie(nonceCookieName, nonce, "/auth", 300))

	codeChallenge := generateCodeChallenge(codeVerifier)
	url := h.oauth2Cfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleCallback validates state/PKCE/nonce, exchanges the code, verifies the ID
// token, enforces email_verified + azp, and issues an opaque server-side session.
func (h *AuthHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Validate state.
	stateCookie, err := r.Cookie(stateCookieName)
	if err != nil || stateCookie.Value == "" {
		writeAuthError(w, http.StatusBadRequest, "missing OAuth state cookie")
		return
	}
	if r.URL.Query().Get("state") != stateCookie.Value {
		writeAuthError(w, http.StatusBadRequest, "OAuth state mismatch (possible CSRF)")
		return
	}

	// Retrieve PKCE verifier + nonce before clearing the transient cookies.
	pkceCookie, perr := r.Cookie(pkceCodeCookie)
	nonceCookie, nerr := r.Cookie(nonceCookieName)

	// Clear the transient cookies regardless of outcome.
	http.SetCookie(w, h.authCookie(stateCookieName, "", "/auth", -1))
	http.SetCookie(w, h.authCookie(pkceCodeCookie, "", "/auth", -1))
	http.SetCookie(w, h.authCookie(nonceCookieName, "", "/auth", -1))

	if perr != nil || pkceCookie.Value == "" {
		writeAuthError(w, http.StatusBadRequest, "missing PKCE verifier cookie")
		return
	}
	if nerr != nil || nonceCookie.Value == "" {
		writeAuthError(w, http.StatusBadRequest, "missing nonce cookie")
		return
	}

	// Check for error from provider.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		log.Warn().Str("error", errParam).Str("description", desc).Msg("auth: OIDC provider returned error")
		writeAuthError(w, http.StatusUnauthorized, fmt.Sprintf("OIDC error: %s", errParam))
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeAuthError(w, http.StatusBadRequest, "missing authorization code")
		return
	}

	// Exchange code for tokens with PKCE verifier.
	token, err := h.oauth2Cfg.Exchange(r.Context(), code,
		oauth2.SetAuthURLParam("code_verifier", pkceCookie.Value),
	)
	if err != nil {
		log.Warn().Err(err).Msg("auth: token exchange failed")
		writeAuthError(w, http.StatusUnauthorized, "token exchange failed")
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		writeAuthError(w, http.StatusInternalServerError, "no id_token in token response")
		return
	}

	idToken, err := h.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Warn().Err(err).Msg("auth: ID token verification failed")
		writeAuthError(w, http.StatusUnauthorized, "ID token verification failed")
		return
	}

	// Bind the token to this auth request via nonce.
	if idToken.Nonce != nonceCookie.Value {
		writeAuthError(w, http.StatusUnauthorized, "nonce mismatch")
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
		Azp           string `json:"azp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		writeAuthError(w, http.StatusUnauthorized, "invalid token claims")
		return
	}

	// Reject a token whose email is explicitly unverified — the email is the identity
	// principal (key ownership, audit attribution), so an unverified address must not
	// be trusted. Absent claim is tolerated (some single-tenant IdPs omit it).
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		writeAuthError(w, http.StatusForbidden, "email not verified")
		return
	}

	// When the token carries multiple audiences, the authorized party (azp) must be
	// this client — otherwise a token minted for a different relying party that merely
	// lists our client_id in aud would be accepted.
	if len(idToken.Audience) > 1 && claims.Azp != h.cfg.ClientID {
		writeAuthError(w, http.StatusUnauthorized, "token azp does not match client")
		return
	}

	// Create an opaque server-side session; the cookie carries only the session ID.
	sid, err := h.store.Create(&UserInfo{Subject: idToken.Subject, Email: claims.Email, Name: claims.Name})
	if err != nil {
		log.Error().Err(err).Msg("auth: failed to create session")
		writeAuthError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	http.SetCookie(w, h.authCookie(sessionCookieName, sid, "/", int(h.store.TTL()/time.Second)))

	http.Redirect(w, r, "/", http.StatusFound)
}

// HandleUserInfo returns the current authenticated user's info.
func (h *AuthHandlers) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeAuthError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(user)
}

// HandleLogout revokes the server-side session and clears the cookie.
func (h *AuthHandlers) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		h.store.Delete(cookie.Value)
	}
	http.SetCookie(w, h.authCookie(sessionCookieName, "", "/", -1))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"logged_out"}`))
}

// HandleRefresh slides the session expiry server-side and re-sets the cookie MaxAge.
func (h *AuthHandlers) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeAuthError(w, http.StatusUnauthorized, "no session to refresh")
		return
	}
	ok, err := h.store.Refresh(cookie.Value)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to refresh session")
		return
	}
	if !ok {
		writeAuthError(w, http.StatusUnauthorized, "session expired or invalid")
		return
	}
	http.SetCookie(w, h.authCookie(sessionCookieName, cookie.Value, "/", int(h.store.TTL()/time.Second)))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"refreshed"}`))
}

// randomString generates a cryptographically random URL-safe base64 string of n bytes.
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge creates an S256 PKCE code challenge from a code verifier.
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
