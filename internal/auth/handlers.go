package auth

import (
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
)

// AuthConfig holds OIDC configuration for the auth handlers.
type AuthConfig struct {
	Enabled         bool
	IssuerURL       string
	ClientID        string
	ClientSecretEnv string
	RedirectURL     string
	Scopes          []string
}

// AuthHandlers implements the OIDC Authorization Code flow with PKCE.
type AuthHandlers struct {
	oauth2Cfg *oauth2.Config
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	cfg       AuthConfig
}

// NewAuthHandlers creates auth handlers by performing OIDC discovery against
// the configured issuer URL.
func NewAuthHandlers(cfg AuthConfig) (*AuthHandlers, error) {
	provider, err := oidc.NewProvider(oidc.InsecureIssuerURLContext(nil, cfg.IssuerURL), cfg.IssuerURL)
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
		oauth2Cfg: oauth2Cfg,
		provider:  provider,
		verifier:  verifier,
		cfg:       cfg,
	}, nil
}

// HandleLogin redirects the user to the OIDC provider's authorization endpoint.
// It generates a state parameter (CSRF protection) and PKCE code verifier.
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

	// Store state in a short-lived httpOnly cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/auth",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Store PKCE verifier in a short-lived httpOnly cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     pkceCodeCookie,
		Value:    codeVerifier,
		Path:     "/auth",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	codeChallenge := generateCodeChallenge(codeVerifier)
	url := h.oauth2Cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	http.Redirect(w, r, url, http.StatusFound)
}

// HandleCallback handles the OIDC provider's redirect back with an authorization code.
// It validates the state parameter, exchanges the code for tokens using PKCE, and
// sets a session cookie with the ID token.
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

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Retrieve PKCE verifier.
	pkceCookie, err := r.Cookie(pkceCodeCookie)
	if err != nil || pkceCookie.Value == "" {
		writeAuthError(w, http.StatusBadRequest, "missing PKCE verifier cookie")
		return
	}

	// Clear the PKCE cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     pkceCodeCookie,
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

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

	// Extract and verify ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		writeAuthError(w, http.StatusInternalServerError, "no id_token in token response")
		return
	}

	_, err = h.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Warn().Err(err).Msg("auth: ID token verification failed")
		writeAuthError(w, http.StatusUnauthorized, "ID token verification failed")
		return
	}

	// Set session cookie with the ID token (httpOnly + Secure + SameSite=Strict).
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    rawIDToken,
		Path:     "/",
		MaxAge:   int(15 * time.Minute / time.Second), // 15 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Redirect to the UI root.
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

// HandleLogout clears the session cookie.
func (h *AuthHandlers) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"logged_out"}`))
}

// HandleRefresh re-verifies the session cookie and reissues it with a fresh expiry.
// In a full implementation this would use a refresh token to obtain a new ID token
// from the provider; for now it extends the session if the current token is still valid.
func (h *AuthHandlers) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeAuthError(w, http.StatusUnauthorized, "no session to refresh")
		return
	}

	_, err = h.verifier.Verify(r.Context(), cookie.Value)
	if err != nil {
		writeAuthError(w, http.StatusUnauthorized, "session token expired or invalid")
		return
	}

	// Re-set the cookie with a fresh MaxAge.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookie.Value,
		Path:     "/",
		MaxAge:   int(15 * time.Minute / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

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
