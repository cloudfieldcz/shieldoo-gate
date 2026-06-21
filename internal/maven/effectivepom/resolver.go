package effectivepom

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// maxDepthCeiling is the absolute maximum parent chain depth that configuration
// cannot exceed. Even if an admin sets max_depth higher, this ceiling applies.
const maxDepthCeiling = 10

// Config holds resolver configuration.
type Config struct {
	Enabled         bool          `mapstructure:"enabled"`
	CacheSize       int           `mapstructure:"cache_size"`
	CacheTTL        time.Duration `mapstructure:"cache_ttl"`
	MaxDepth        int           `mapstructure:"max_depth"`
	FetchTimeout    time.Duration `mapstructure:"fetch_timeout"`
	ResolverTimeout time.Duration `mapstructure:"resolver_timeout"`
}

// Resolver fetches standalone .pom files from a Maven repository and walks
// the parent chain to find an explicit <licenses> declaration. It is safe
// for concurrent use.
type Resolver struct {
	upstreamURL     string
	client          *http.Client
	cache           *pomCache
	maxDepth        int
	fetchTimeout    time.Duration
	resolverTimeout time.Duration
}

// NewResolver creates a Resolver. The client should be the shared HTTP client
// from the Maven adapter (inherits proxy TLS settings, transport-level auth).
// The resolver never constructs its own HTTP client.
func NewResolver(upstreamURL string, client *http.Client, cfg Config) *Resolver {
	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 5
	}
	if maxDepth > maxDepthCeiling {
		maxDepth = maxDepthCeiling
	}
	fetchTimeout := cfg.FetchTimeout
	if fetchTimeout <= 0 {
		fetchTimeout = 3 * time.Second
	}
	resolverTimeout := cfg.ResolverTimeout
	if resolverTimeout <= 0 {
		resolverTimeout = 5 * time.Second
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 24 * time.Hour
	}
	cacheSize := cfg.CacheSize
	if cacheSize <= 0 {
		cacheSize = 4096
	}

	return &Resolver{
		upstreamURL:     strings.TrimRight(upstreamURL, "/"),
		client:          client,
		cache:           newPOMCache(cacheSize, cacheTTL),
		maxDepth:        maxDepth,
		fetchTimeout:    fetchTimeout,
		resolverTimeout: resolverTimeout,
	}
}

// Resolve walks the parent POM chain for the given coordinates and returns the
// first set of licenses found. Returns nil (not an error) when:
//   - network failure (fail-open)
//   - depth limit exceeded
//   - cycle detected
//   - no licenses found anywhere in the chain
//
// Errors are logged but never propagated — the resolver is a best-effort
// enrichment, not a gate.
func (r *Resolver) Resolve(ctx context.Context, c Coords) []string {
	return r.ResolveFrom(ctx, c, r.upstreamURL, "")
}

// ResolveFrom walks the parent POM chain for the coordinates against a SPECIFIC
// base URL (the serving upstream index the artifact was fetched from) with an
// optional Authorization header (the index's per-index credential). The entire
// walk is pinned to baseURL — parents are NOT re-resolved across indexes
// (best-effort license enrichment, fail-open; pinning avoids a dependency-
// confusion surface). The per-(baseURL,GAV) cache key prevents cross-index
// license bleed.
//
// Returns nil (not an error) on network failure, depth/cycle limits, or no
// licenses found. Errors are logged, never propagated — the resolver is
// best-effort enrichment, not a gate.
func (r *Resolver) ResolveFrom(ctx context.Context, c Coords, baseURL, authHeader string) []string {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		baseURL = r.upstreamURL
	}

	// Apply resolver-level timeout (caps the entire parent chain walk).
	ctx, cancel := context.WithTimeout(ctx, r.resolverTimeout)
	defer cancel()

	seen := make(map[string]bool, r.maxDepth)
	current := c
	for depth := 0; depth < r.maxDepth; depth++ {
		key := current.String()

		// Cycle detection.
		if seen[key] {
			log.Warn().Str("coords", key).Msg("effectivepom: cycle detected in parent chain")
			return nil
		}
		seen[key] = true

		// Cache hit? Keyed by (baseURL, GAV) so the same GAV from a different
		// index is not served stale license data.
		cacheKey := baseURL + "|" + key
		if cached := r.cache.get(cacheKey); cached != nil {
			if len(cached.Licenses) > 0 {
				return cached.Licenses
			}
			if cached.Parent != nil {
				current = *cached.Parent
				continue
			}
			// Cached but no licenses and no parent — dead end.
			return nil
		}

		// Fetch the standalone .pom from the serving index.
		result, err := r.fetchAndParse(ctx, current, baseURL, authHeader)
		if err != nil {
			log.Warn().Err(err).Str("coords", key).Msg("effectivepom: fetch/parse failed, failing open")
			return nil
		}

		// Cache the result (even empty — prevents re-fetching dead ends).
		r.cache.put(cacheKey, result)

		if len(result.Licenses) > 0 {
			return result.Licenses
		}
		if result.Parent != nil {
			current = *result.Parent
			continue
		}
		// No licenses and no parent — end of chain.
		return nil
	}

	log.Warn().Str("coords", c.String()).Int("max_depth", r.maxDepth).Msg("effectivepom: max depth exceeded")
	return nil
}

// fetchAndParse downloads a standalone .pom from baseURL (with optional auth) and parses it.
func (r *Resolver) fetchAndParse(ctx context.Context, c Coords, baseURL, authHeader string) (*pomResult, error) {
	pomURL := r.pomURL(baseURL, c)

	// Per-POM fetch timeout.
	fetchCtx, cancel := context.WithTimeout(ctx, r.fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, pomURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", pomURL, err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", pomURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", pomURL, resp.StatusCode)
	}

	// Defence in depth (the client is also redirect-safe): reject a cross-host
	// redirect so a private POM fetch's credential cannot be exfiltrated.
	if resp.Request != nil && resp.Request.URL != nil {
		origHost := mustParseHost(pomURL)
		finalHost := resp.Request.URL.Host
		if origHost != "" && finalHost != "" && origHost != finalHost {
			return nil, fmt.Errorf("effectivepom: cross-host redirect detected (%s → %s), rejecting", origHost, finalHost)
		}
	}

	return parsePOM(resp.Body)
}

// pomURL constructs the standalone .pom URL against baseURL:
// {baseURL}/{groupPath}/{artifactId}/{version}/{artifactId}-{version}.pom
func (r *Resolver) pomURL(baseURL string, c Coords) string {
	groupPath := strings.ReplaceAll(c.GroupID, ".", "/")
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom",
		baseURL, groupPath, c.ArtifactID, c.Version, c.ArtifactID, c.Version)
}

// mustParseHost extracts the host from a URL, returning "" on error.
func mustParseHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}
