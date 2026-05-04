package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// registryToken holds a cached auth token for a registry.
type registryToken struct {
	Token     string
	ExpiresAt time.Time
}

// tokenExchanger handles Docker Registry v2 Bearer token exchange.
// See https://distribution.github.io/distribution/spec/auth/token/
type tokenExchanger struct {
	httpClient *http.Client
	mu         sync.Mutex
	cache      map[string]*registryToken // key: "realm|service|scope"
}

// newTokenExchanger creates a tokenExchanger with the given HTTP client.
func newTokenExchanger(client *http.Client) *tokenExchanger {
	return &tokenExchanger{
		httpClient: client,
		cache:      make(map[string]*registryToken),
	}
}

// tokenResponse is the JSON body returned by a Docker auth realm endpoint.
type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
}

// parseWwwAuthenticate parses a Docker-style Www-Authenticate header:
//
//	Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"
//
// Returns (realm, service, scope, ok). scope may be empty for some registries.
func parseWwwAuthenticate(header string) (realm, service, scope string, ok bool) {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "Bearer ") {
		return "", "", "", false
	}
	params := header[len("Bearer "):]

	parsed := make(map[string]string)
	for _, part := range splitWwwAuthParams(params) {
		part = strings.TrimSpace(part)
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eqIdx])
		val := strings.TrimSpace(part[eqIdx+1:])
		// Strip surrounding quotes.
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		parsed[key] = val
	}

	realm = parsed["realm"]
	service = parsed["service"]
	scope = parsed["scope"]

	if realm == "" {
		return "", "", "", false
	}
	return realm, service, scope, true
}

// splitWwwAuthParams splits comma-separated parameters, respecting quoted strings.
func splitWwwAuthParams(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuotes = !inQuotes
			current.WriteByte(c)
		} else if c == ',' && !inQuotes {
			parts = append(parts, current.String())
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// cacheKey returns the map key for a (realm, service, scope) tuple.
func cacheKey(realm, service, scope string) string {
	return realm + "|" + service + "|" + scope
}

// exchangeToken calls the auth realm URL to get a Bearer token.
// Tokens are cached until they expire (with a 30-second safety margin).
func (te *tokenExchanger) exchangeToken(ctx context.Context, realm, service, scope string) (string, error) {
	key := cacheKey(realm, service, scope)

	te.mu.Lock()
	if cached, ok := te.cache[key]; ok && time.Now().Before(cached.ExpiresAt) {
		token := cached.Token
		te.mu.Unlock()
		return token, nil
	}
	te.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, nil)
	if err != nil {
		return "", fmt.Errorf("docker: token exchange: building request: %w", err)
	}

	q := req.URL.Query()
	if service != "" {
		q.Set("service", service)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := te.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("docker: token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Surface the upstream response body so opaque WAF / rate-limit rejections
		// (e.g. Cloudflare 403 with a TOOMANYREQUESTS body) are diagnosable from
		// logs alone instead of requiring a code change to capture them.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("docker: token exchange: auth server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("docker: token exchange: decoding response: %w", err)
	}

	if tokenResp.Token == "" {
		return "", fmt.Errorf("docker: token exchange: empty token in response")
	}

	// Cache the token. Default to 60 seconds if expires_in is missing.
	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 60
	}
	// Subtract 30 seconds as a safety margin.
	expiry := time.Now().Add(time.Duration(expiresIn)*time.Second - 30*time.Second)

	te.mu.Lock()
	te.cache[key] = &registryToken{
		Token:     tokenResp.Token,
		ExpiresAt: expiry,
	}
	te.mu.Unlock()

	log.Debug().
		Str("realm", realm).
		Str("service", service).
		Str("scope", scope).
		Int("expires_in", expiresIn).
		Msg("docker: token exchange successful")

	return tokenResp.Token, nil
}
