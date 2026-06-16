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

// scopeSatisfies reports whether the held scope list satisfies a required scope.
// The wildcard "*" (global super-token) satisfies any requirement, an exact match
// satisfies, and admin:write implies admin:read (a writer can always read). No
// other implications exist — proxy:fetch, scan:upload, and admin are orthogonal
// least-privilege roles.
func scopeSatisfies(held []string, required string) bool {
	for _, s := range held {
		switch {
		case s == "*":
			return true
		case s == required:
			return true
		case required == model.ScopeAdminRead && s == model.ScopeAdminWrite:
			return true
		}
	}
	return false
}

// ScopeSatisfiedBy reports whether the held scope list satisfies required (honoring
// the "*" wildcard and admin:write⇒admin:read). Exported for callers that need to
// check scope possession outside middleware (e.g. API-key minting subset checks).
func ScopeSatisfiedBy(held []string, required string) bool {
	return scopeSatisfies(held, required)
}

// RequireScope returns an http middleware that 403s any request whose held scopes
// do not satisfy scope. Global-super-token ("*") requests always pass, and
// admin:write satisfies an admin:read requirement (see scopeSatisfies).
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scopeSatisfies(ScopesFromContext(r.Context()), scope) {
				next.ServeHTTP(w, r)
				return
			}
			writeForbidden(w, scope)
		})
	}
}

// RequireScopeByMethod returns middleware that derives the required admin scope
// from the HTTP method: GET/HEAD/OPTIONS require admin:read, every other verb
// requires admin:write.
//
// The rule is about the *authorization class*, NOT literal statelessness: a GET
// may still perform security bookkeeping with side effects — e.g. GET …/sbom
// recomputes the SBOM SHA-256 and, on mismatch, marks integrity_violated and
// writes an sbom_integrity_violation audit row (Security Invariant 7). Those
// reads correctly require only admin:read; do not "fix" that UPDATE away to
// satisfy a naive read-only reading of this comment.
func RequireScopeByMethod() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			required := model.ScopeAdminWrite
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				required = model.ScopeAdminRead
			}
			if scopeSatisfies(ScopesFromContext(r.Context()), required) {
				next.ServeHTTP(w, r)
				return
			}
			writeForbidden(w, required)
		})
	}
}

// writeForbidden emits the canonical 403 JSON body naming the missing scope.
func writeForbidden(w http.ResponseWriter, scope string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"forbidden","message":"missing scope ` + scope + `"}`))
}

// ScopesFromAPIKey returns the canonical scope list for an APIKey, defaulting to
// proxy:fetch when the column is empty.
func ScopesFromAPIKey(k *model.APIKey) []string {
	if k == nil {
		return nil
	}
	return model.ScopeList(k.Scopes)
}
