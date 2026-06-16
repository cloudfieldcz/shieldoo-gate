package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func remoteAddrAfter(t *testing.T, cidrs []string, peer string, headers map[string]string) string {
	t.Helper()
	var got string
	h := TrustedProxyMiddleware(cidrs)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.RemoteAddr
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = peer
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

// With no trusted proxies, forwarding headers must be ignored entirely.
func TestTrustedProxy_NoneConfigured_IgnoresHeaders(t *testing.T) {
	got := remoteAddrAfter(t, nil, "198.51.100.9:5000", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
		"X-Real-IP":       "1.2.3.4",
	})
	assert.Equal(t, "198.51.100.9:5000", got, "untrusted peer headers must be ignored")
}

// An untrusted peer cannot spoof its IP via X-Forwarded-For.
func TestTrustedProxy_UntrustedPeer_CannotSpoof(t *testing.T) {
	got := remoteAddrAfter(t, []string{"10.0.0.0/8"}, "198.51.100.9:5000", map[string]string{
		"X-Forwarded-For": "1.2.3.4",
	})
	assert.Equal(t, "198.51.100.9:5000", got, "peer outside trusted CIDR must not be rewritten")
}

// Behind a trusted proxy, the right-most untrusted XFF entry is used as the client.
func TestTrustedProxy_TrustedPeer_UsesRightmostUntrusted(t *testing.T) {
	got := remoteAddrAfter(t, []string{"10.0.0.0/8"}, "10.0.0.5:443", map[string]string{
		// client, then an internal trusted hop.
		"X-Forwarded-For": "203.0.113.7, 10.0.0.9",
	})
	assert.Equal(t, "203.0.113.7", got, "should skip trusted hops and pick the real client")
}

// X-Real-IP is the fallback when no usable XFF entry exists.
func TestTrustedProxy_TrustedPeer_FallsBackToXRealIP(t *testing.T) {
	got := remoteAddrAfter(t, []string{"10.0.0.0/8"}, "10.0.0.5:443", map[string]string{
		"X-Real-IP": "203.0.113.7",
	})
	assert.Equal(t, "203.0.113.7", got)
}

// A bare IP entry in the trusted list is treated as a single host.
func TestTrustedProxy_BareIPEntry(t *testing.T) {
	got := remoteAddrAfter(t, []string{"10.0.0.5"}, "10.0.0.5:443", map[string]string{
		"X-Forwarded-For": "203.0.113.7",
	})
	assert.Equal(t, "203.0.113.7", got)
}
