package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func runCSRF(t *testing.T, allowed []string, method string, withCookie bool, headers map[string]string) int {
	t.Helper()
	called := false
	h := CSRFGuard(allowed)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true }))
	req := httptest.NewRequest(method, "https://gate.example.com/api/v1/artifacts/x/release", nil)
	req.Host = "gate.example.com"
	if withCookie {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "sid"})
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK || called {
		return http.StatusOK
	}
	return rec.Code
}

func TestCSRF_SafeMethod_Allowed(t *testing.T) {
	assert.Equal(t, http.StatusOK, runCSRF(t, nil, "GET", true, nil))
}

func TestCSRF_TokenAuth_Bypasses(t *testing.T) {
	// Authorization header present → not CSRF-prone, even cross-origin.
	code := runCSRF(t, nil, "POST", true, map[string]string{
		"Authorization": "Bearer sgw_x",
		"Origin":        "https://evil.example.com",
	})
	assert.Equal(t, http.StatusOK, code)
}

func TestCSRF_NoSessionCookie_Bypasses(t *testing.T) {
	assert.Equal(t, http.StatusOK, runCSRF(t, nil, "POST", false, nil))
}

func TestCSRF_CookieSameOrigin_Allowed(t *testing.T) {
	code := runCSRF(t, nil, "POST", true, map[string]string{"Origin": "https://gate.example.com"})
	assert.Equal(t, http.StatusOK, code)
}

func TestCSRF_CookieCrossOrigin_Blocked(t *testing.T) {
	code := runCSRF(t, nil, "POST", true, map[string]string{"Origin": "https://evil.example.com"})
	assert.Equal(t, http.StatusForbidden, code)
}

func TestCSRF_CookieNoOrigin_Blocked(t *testing.T) {
	// A cookie-authenticated mutation with neither Origin nor Referer nor custom
	// header must be rejected.
	code := runCSRF(t, nil, "POST", true, nil)
	assert.Equal(t, http.StatusForbidden, code)
}

func TestCSRF_CustomHeaderFallback_Allowed(t *testing.T) {
	code := runCSRF(t, nil, "POST", true, map[string]string{CSRFHeaderName: "1"})
	assert.Equal(t, http.StatusOK, code)
}

func TestCSRF_RefererFallback_SameOrigin_Allowed(t *testing.T) {
	code := runCSRF(t, nil, "POST", true, map[string]string{"Referer": "https://gate.example.com/ui/artifacts"})
	assert.Equal(t, http.StatusOK, code)
}

func TestCSRF_AllowlistOrigin_Allowed(t *testing.T) {
	code := runCSRF(t, []string{"https://admin.example.com"}, "POST", true,
		map[string]string{"Origin": "https://admin.example.com"})
	assert.Equal(t, http.StatusOK, code)
}
