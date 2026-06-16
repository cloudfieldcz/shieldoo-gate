package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// CSRFHeaderName is a custom header the SPA may set on mutating requests. Cross-site
// HTML forms cannot set custom headers, and a cross-site fetch that tries to set one
// triggers a CORS preflight that same-origin policy blocks — so its presence is an
// alternative proof the request is same-origin when Origin/Referer are absent.
const CSRFHeaderName = "X-Shieldoo-CSRF"

// CSRFGuard returns middleware that blocks cross-site state-changing requests that
// authenticate via the session cookie. SameSite=Lax already stops classic cross-site
// form POSTs; this adds an explicit Origin/Referer same-origin check as defense in
// depth on cookie-authenticated mutations.
//
// It deliberately does NOTHING for:
//   - safe methods (GET/HEAD/OPTIONS),
//   - token-authenticated requests (an Authorization header is present — browsers
//     never attach it automatically cross-site, so those calls aren't CSRF-prone),
//   - requests with no session cookie (not browser/cookie-authenticated).
//
// When allowedOrigins is non-empty the Origin must match one of them; otherwise the
// Origin host must equal the request Host (same-origin).
func CSRFGuard(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(strings.TrimSuffix(o, "/"))
		if o != "" {
			allowed[strings.ToLower(o)] = true
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if csrfSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get("Authorization") != "" {
				next.ServeHTTP(w, r)
				return
			}
			if c, err := r.Cookie(sessionCookieName); err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			if csrfOriginOK(r, allowed) || r.Header.Get(CSRFHeaderName) != "" {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","message":"CSRF check failed: cross-site or missing Origin on a cookie-authenticated request"}`))
		})
	}
}

func csrfSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// csrfOriginOK reports whether the request's Origin (or Referer fallback) is trusted.
func csrfOriginOK(r *http.Request, allowed map[string]bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			if u, err := url.Parse(ref); err == nil && u.Host != "" {
				origin = u.Scheme + "://" + u.Host
			}
		}
	}
	if origin == "" {
		return false
	}
	if len(allowed) > 0 {
		return allowed[strings.ToLower(origin)]
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
