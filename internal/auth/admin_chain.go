package auth

import (
	"net/http"
)

// AdminAuthChain composes PATBearerMiddleware (try first) with OIDC (fallback). When
// the request carries an Authorization Bearer header, the PAT path runs and either
// authenticates or returns 401. When no Authorization header is present, the OIDC
// middleware takes over (cookie-based session).
//
// OIDC sessions implicitly receive admin:read,admin:write scopes (the admin UI is the
// canonical OIDC consumer; users with valid sessions are operators by definition).
type AdminAuthChain struct {
	PAT  *PATBearerMiddleware
	OIDC *OIDCMiddleware
}

// NewAdminAuthChain constructs the chain. Either PAT or OIDC may be nil; when both
// are nil the chain is a no-op (admin endpoints reachable without auth — used in dev).
func NewAdminAuthChain(pat *PATBearerMiddleware, oidc *OIDCMiddleware) *AdminAuthChain {
	return &AdminAuthChain{PAT: pat, OIDC: oidc}
}

// Authenticate returns a chi-compatible middleware function.
func (c *AdminAuthChain) Authenticate(next http.Handler) http.Handler {
	// Order: PAT first (sets scopes when token present), then OIDC fallback (cookie auth).
	// We wrap the OIDC layer to inject implicit admin scopes when the request reached it
	// via cookie (no Bearer header present).
	oidcWrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scopes := ScopesFromContext(r.Context()); len(scopes) > 0 {
			// Already authenticated by PAT — pass through.
			next.ServeHTTP(w, r)
			return
		}
		if c.OIDC == nil {
			// No OIDC available; defer to next (chi.Recoverer / handler 401s as needed).
			next.ServeHTTP(w, r)
			return
		}
		// Wrap next with implicit-scope injection so the OIDC handler can attach
		// scopes after it sets the user.
		injected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if u := UserFromContext(ctx); u != nil && len(ScopesFromContext(ctx)) == 0 {
				ctx = WithScopes(ctx, []string{"admin:read", "admin:write"})
				ctx = WithScopeKey(ctx, "oidc:"+u.Email)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
		c.OIDC.Authenticate(injected).ServeHTTP(w, r)
	})

	if c.PAT == nil {
		return oidcWrapped
	}
	return c.PAT.Authenticate(oidcWrapped)
}
