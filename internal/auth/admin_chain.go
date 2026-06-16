package auth

import (
	"net/http"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
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

	// allowUnauthenticated, when true, lets a request that carried no PAT/global
	// token AND has no OIDC fallback proceed WITHOUT any credentials. This is the
	// explicit no-auth dev mode (neither auth nor proxy_auth enabled). It defaults
	// to false so the chain FAILS CLOSED: in proxy-auth-only deployments (proxy_auth
	// on, OIDC off) an anonymous request to the admin API is rejected rather than
	// silently falling through to the handler (CVE-class "open admin API" footgun).
	allowUnauthenticated bool
}

// NewAdminAuthChain constructs the chain. Either PAT or OIDC may be nil. The chain
// fails CLOSED by default — call AllowUnauthenticated(true) only for the explicit
// no-auth dev mode where the admin API is intentionally open.
func NewAdminAuthChain(pat *PATBearerMiddleware, oidc *OIDCMiddleware) *AdminAuthChain {
	return &AdminAuthChain{PAT: pat, OIDC: oidc}
}

// AllowUnauthenticated opts the chain into leaving the admin API open when no
// credential is presented and no OIDC fallback exists. Chainable. Use ONLY for the
// no-auth dev mode (neither auth nor proxy_auth enabled).
func (c *AdminAuthChain) AllowUnauthenticated(allow bool) *AdminAuthChain {
	c.allowUnauthenticated = allow
	return c
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
			// No PAT/global token was presented and there is no OIDC fallback.
			// Fail closed unless this deployment explicitly allows an open admin API.
			if c.allowUnauthenticated {
				next.ServeHTTP(w, r)
				return
			}
			writeAuthError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// Wrap next with implicit-scope injection so the OIDC handler can attach
		// scopes after it sets the user.
		injected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if u := UserFromContext(ctx); u != nil && len(ScopesFromContext(ctx)) == 0 {
				// OIDC operators are full admins, including API-key management.
				ctx = WithScopes(ctx, []string{model.ScopeAdminRead, model.ScopeAdminWrite, model.ScopeKeysManage})
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
