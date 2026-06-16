package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// OIDCMiddleware authenticates admin-UI requests using the server-side session cookie.
//
// It does NOT accept OIDC ID tokens on the Authorization header. API clients must use
// a PAT (see PATBearerMiddleware); the ID token is an authentication assertion, not an
// API access token, so accepting it as a bearer was token-type confusion. The cookie
// now carries an opaque session ID (not the raw ID token), validated against the store.
type OIDCMiddleware struct {
	store *SessionStore
}

// NewOIDCMiddleware creates middleware that validates the session cookie against store.
func NewOIDCMiddleware(store *SessionStore) *OIDCMiddleware {
	return &OIDCMiddleware{store: store}
}

// Authenticate returns HTTP middleware that requires a valid session cookie.
// Browser requests without a session are redirected to login; API clients get 401 JSON.
func (m *OIDCMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			m.deny(w, r)
			return
		}
		user, ok := m.store.Validate(cookie.Value)
		if !ok {
			m.deny(w, r)
			return
		}
		ctx := ContextWithUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// deny redirects browsers to login and returns 401 JSON to API clients.
func (m *OIDCMiddleware) deny(w http.ResponseWriter, r *http.Request) {
	if isBrowserRequest(r) {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}
	writeAuthError(w, http.StatusUnauthorized, "missing or invalid session")
}

// isBrowserRequest returns true when the request likely comes from a web browser
// (accepts HTML) rather than an API client (accepts JSON / no Accept header).
func isBrowserRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html")
}

// writeAuthError writes a JSON 401/403 error response.
func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": message})
	_, _ = w.Write(body)
}
