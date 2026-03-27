package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWwwAuthenticate_Valid_FullHeader(t *testing.T) {
	header := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`
	realm, service, scope, ok := parseWwwAuthenticate(header)
	assert.True(t, ok)
	assert.Equal(t, "https://auth.docker.io/token", realm)
	assert.Equal(t, "registry.docker.io", service)
	assert.Equal(t, "repository:library/nginx:pull", scope)
}

func TestParseWwwAuthenticate_Valid_RealmOnly(t *testing.T) {
	header := `Bearer realm="https://ghcr.io/token"`
	realm, service, scope, ok := parseWwwAuthenticate(header)
	assert.True(t, ok)
	assert.Equal(t, "https://ghcr.io/token", realm)
	assert.Empty(t, service)
	assert.Empty(t, scope)
}

func TestParseWwwAuthenticate_Valid_WithExtraSpaces(t *testing.T) {
	header := `Bearer  realm="https://auth.example.com/token" , service="example.com" , scope="repository:myimage:pull"`
	realm, service, scope, ok := parseWwwAuthenticate(header)
	assert.True(t, ok)
	assert.Equal(t, "https://auth.example.com/token", realm)
	assert.Equal(t, "example.com", service)
	assert.Equal(t, "repository:myimage:pull", scope)
}

func TestParseWwwAuthenticate_Invalid_NotBearer(t *testing.T) {
	header := `Basic realm="registry"`
	_, _, _, ok := parseWwwAuthenticate(header)
	assert.False(t, ok)
}

func TestParseWwwAuthenticate_Invalid_EmptyString(t *testing.T) {
	_, _, _, ok := parseWwwAuthenticate("")
	assert.False(t, ok)
}

func TestParseWwwAuthenticate_Invalid_BearerNoRealm(t *testing.T) {
	header := `Bearer service="registry.docker.io"`
	_, _, _, ok := parseWwwAuthenticate(header)
	assert.False(t, ok)
}

func TestTokenExchanger_ExchangesToken_Success(t *testing.T) {
	expectedToken := "test-bearer-token-abc123"

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "registry.docker.io", r.URL.Query().Get("service"))
		assert.Equal(t, "repository:library/nginx:pull", r.URL.Query().Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Token:     expectedToken,
			ExpiresIn: 300,
		})
	}))
	defer authServer.Close()

	te := newTokenExchanger(&http.Client{Timeout: 5 * time.Second})

	token, err := te.exchangeToken(
		context.Background(),
		authServer.URL,
		"registry.docker.io",
		"repository:library/nginx:pull",
	)
	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)
}

func TestTokenExchanger_ExchangesToken_AuthServerError(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer authServer.Close()

	te := newTokenExchanger(&http.Client{Timeout: 5 * time.Second})

	_, err := te.exchangeToken(
		context.Background(),
		authServer.URL,
		"registry.docker.io",
		"repository:library/nginx:pull",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth server returned 500")
}

func TestTokenExchanger_ExchangesToken_EmptyToken(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{Token: "", ExpiresIn: 300})
	}))
	defer authServer.Close()

	te := newTokenExchanger(&http.Client{Timeout: 5 * time.Second})

	_, err := te.exchangeToken(context.Background(), authServer.URL, "svc", "scope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty token")
}

func TestTokenExchanger_CachesToken(t *testing.T) {
	callCount := 0
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Token:     "cached-token",
			ExpiresIn: 300,
		})
	}))
	defer authServer.Close()

	te := newTokenExchanger(&http.Client{Timeout: 5 * time.Second})

	// First call — should hit the auth server.
	token1, err := te.exchangeToken(context.Background(), authServer.URL, "svc", "scope")
	require.NoError(t, err)
	assert.Equal(t, "cached-token", token1)
	assert.Equal(t, 1, callCount)

	// Second call — should use cache.
	token2, err := te.exchangeToken(context.Background(), authServer.URL, "svc", "scope")
	require.NoError(t, err)
	assert.Equal(t, "cached-token", token2)
	assert.Equal(t, 1, callCount, "expected token to be served from cache, no second request")
}

func TestTokenExchanger_CacheExpiry_RefetchesToken(t *testing.T) {
	callCount := 0
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			Token:     "refreshed-token",
			ExpiresIn: 1, // expires in 1 second, minus 30s margin = already expired
		})
	}))
	defer authServer.Close()

	te := newTokenExchanger(&http.Client{Timeout: 5 * time.Second})

	// First call.
	_, err := te.exchangeToken(context.Background(), authServer.URL, "svc", "scope")
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Second call — token is expired (1s - 30s margin = already past), should re-fetch.
	_, err = te.exchangeToken(context.Background(), authServer.URL, "svc", "scope")
	require.NoError(t, err)
	assert.Equal(t, 2, callCount, "expected cache miss due to expiry")
}
