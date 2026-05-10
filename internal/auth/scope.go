package auth

import (
	"context"
	"net/http"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// scopesContextKey is the context key under which the authenticated scopes are stored.
type scopesContextKey struct{}

// scopeKeyContextKey is the context key under which the rate-limit identity (api_key.id
// or "global-token" or "oidc:<email>") is stored.
type scopeKeyContextKey struct{}

// WithScopes returns a context carrying the authenticated scope list.
func WithScopes(ctx context.Context, scopes []string) context.Context {
	return context.WithValue(ctx, scopesContextKey{}, scopes)
}

// ScopesFromContext returns the scope list set by an auth middleware. Empty slice if absent.
func ScopesFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(scopesContextKey{}).([]string)
	return v
}

// WithScopeKey stores the rate-limit identity for the request.
func WithScopeKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, scopeKeyContextKey{}, key)
}

// ScopeKeyFromContext returns the identity string used for rate-limit bucketing.
func ScopeKeyFromContext(ctx context.Context) string {
	v, _ := ctx.Value(scopeKeyContextKey{}).(string)
	return v
}

// HasScope returns true when the request context carries scope.
func HasScope(ctx context.Context, scope string) bool {
	for _, s := range ScopesFromContext(ctx) {
		if s == scope {
			return true
		}
	}
	return false
}

// RequireScope returns an http middleware that 403s any request whose context does
// not carry scope. Global-super-token requests always pass.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if HasScope(r.Context(), "*") || HasScope(r.Context(), scope) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","message":"missing scope ` + scope + `"}`))
		})
	}
}

// ScopesFromAPIKey returns the canonical scope list for an APIKey, defaulting to
// proxy:fetch when the column is empty.
func ScopesFromAPIKey(k *model.APIKey) []string {
	if k == nil {
		return nil
	}
	return model.ScopeList(k.Scopes)
}
