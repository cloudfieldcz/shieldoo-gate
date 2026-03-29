package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
)

// OIDCMiddleware validates JWT Bearer tokens from the Authorization header
// using OIDC discovery and JWKS verification.
type OIDCMiddleware struct {
	verifier *oidc.IDTokenVerifier
	clientID string
}

// NewOIDCMiddleware creates a new middleware that discovers OIDC configuration
// from the issuer URL and verifies tokens against the provider's JWKS.
func NewOIDCMiddleware(ctx context.Context, issuerURL, clientID string) (*OIDCMiddleware, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &OIDCMiddleware{
		verifier: verifier,
		clientID: clientID,
	}, nil
}

// Authenticate returns HTTP middleware that validates Bearer JWT tokens.
// On success, the verified user identity is stored in the request context.
// On failure, it returns 401 Unauthorized with a JSON error body.
func (m *OIDCMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First try Authorization header (API clients).
		rawToken := extractBearerToken(r)

		// Fall back to session cookie (UI flow).
		if rawToken == "" {
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				rawToken = cookie.Value
			}
		}

		if rawToken == "" {
			writeAuthError(w, http.StatusUnauthorized, "missing bearer token or session cookie")
			return
		}

		idToken, err := m.verifier.Verify(r.Context(), rawToken)
		if err != nil {
			log.Debug().Err(err).Msg("auth: token verification failed")
			writeAuthError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		// Extract standard claims.
		var claims struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			log.Warn().Err(err).Msg("auth: failed to parse token claims")
			writeAuthError(w, http.StatusUnauthorized, "invalid token claims")
			return
		}

		user := &UserInfo{
			Subject: idToken.Subject,
			Email:   claims.Email,
			Name:    claims.Name,
		}

		ctx := ContextWithUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractBearerToken extracts the token from "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// writeAuthError writes a JSON 401/403 error response.
func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]string{"error": message})
	_, _ = w.Write(body)
}
