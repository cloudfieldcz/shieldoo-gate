// Package docker implements a read-only OCI Distribution Spec pull proxy adapter.
package docker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ adapter.Adapter = (*DockerAdapter)(nil)

// DockerAdapter proxies OCI Distribution Spec read-only pull requests to an
// upstream registry (e.g. Docker Hub, GHCR, private registry).
//
// Scanning Docker images end-to-end requires pulling and analysing the full
// image manifest + layers via Trivy, which is handled out-of-band in v1.0.
// This adapter forwards pull traffic transparently.
type DockerAdapter struct {
	db          *sqlx.DB
	cache       cache.CacheStore
	policyEng   *policy.Engine
	upstreamURL string
	router      http.Handler
	httpClient  *http.Client
}

// NewDockerAdapter creates and wires a DockerAdapter.
func NewDockerAdapter(
	db *sqlx.DB,
	cacheStore cache.CacheStore,
	policyEngine *policy.Engine,
	upstreamURL string,
) *DockerAdapter {
	a := &DockerAdapter{
		db:          db,
		cache:       cacheStore,
		policyEng:   policyEngine,
		upstreamURL: strings.TrimRight(upstreamURL, "/"),
		httpClient:  &http.Client{Timeout: 10 * time.Minute},
	}
	a.router = a.buildRouter()
	return a
}

// Ecosystem implements adapter.Adapter.
func (a *DockerAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemDocker }

// HealthCheck implements adapter.Adapter.
func (a *DockerAdapter) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+"/v2/", nil)
	if err != nil {
		return fmt.Errorf("docker: health check: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("docker: health check: %w", err)
	}
	resp.Body.Close()
	// Docker registries return 200 or 401 (auth required) on /v2/ — both indicate the service is up.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("docker: health check: upstream returned %d", resp.StatusCode)
	}
	return nil
}

// ServeHTTP implements adapter.Adapter (and http.Handler).
func (a *DockerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// buildRouter creates chi routes for the OCI Distribution Spec v2 API.
func (a *DockerAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()

	// OCI v2 API version check.
	r.Get("/v2/", a.handleV2Check)

	// Manifests and blobs — image names can contain slashes (multi-component
	// names like "library/nginx" or "org/team/image"). We use a catch-all
	// route and parse the path manually.
	r.Get("/v2/*", a.handleV2Wildcard)

	return r
}

// handleV2Check responds with the Docker-Distribution-API-Version header as
// required by the OCI Distribution Spec.
func (a *DockerAdapter) handleV2Check(w http.ResponseWriter, r *http.Request) {
	// Try to proxy to upstream to preserve auth challenges, but if upstream
	// is unreachable, return a synthetic 200 with the required header.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.upstreamURL+"/v2/", nil)
	if err != nil {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	// Forward Authorization header if present.
	if auth := r.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		// Fail gracefully — return the required header.
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	// Ensure the version header is always present.
	if w.Header().Get("Docker-Distribution-API-Version") == "" {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleV2Wildcard routes /v2/* requests to manifests or blobs handlers.
// It parses the path manually because OCI image names can contain slashes.
//
// Expected path forms:
//   - /v2/{name}/manifests/{ref}
//   - /v2/{name}/blobs/{digest}
func (a *DockerAdapter) handleV2Wildcard(w http.ResponseWriter, r *http.Request) {
	// chi wildcard gives us everything after /v2/
	wildcardPath := chi.URLParam(r, "*")

	// Try to match /manifests/ or /blobs/ as the last two-segment suffix.
	manifestsIdx := strings.LastIndex(wildcardPath, "/manifests/")
	blobsIdx := strings.LastIndex(wildcardPath, "/blobs/")

	switch {
	case manifestsIdx > 0:
		name := wildcardPath[:manifestsIdx]
		ref := wildcardPath[manifestsIdx+len("/manifests/"):]
		if err := validateDockerName(name); err != nil {
			adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
				Error:  "invalid image name",
				Reason: err.Error(),
			})
			return
		}
		a.proxyUpstream(w, r, "/v2/"+name+"/manifests/"+ref)

	case blobsIdx > 0:
		name := wildcardPath[:blobsIdx]
		digest := wildcardPath[blobsIdx+len("/blobs/"):]
		if err := validateDockerName(name); err != nil {
			adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
				Error:  "invalid image name",
				Reason: err.Error(),
			})
			return
		}
		a.proxyUpstream(w, r, "/v2/"+name+"/blobs/"+digest)

	default:
		http.NotFound(w, r)
	}
}

// proxyUpstream forwards the request to the upstream registry and relays the response.
func (a *DockerAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, path string) {
	target := a.upstreamURL + path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}

	// Forward relevant headers: Accept, Authorization, Docker-specific.
	for _, hdr := range []string{"Accept", "Authorization", "Docker-Content-Digest"} {
		if v := r.Header.Get(hdr); v != "" {
			req.Header.Set(hdr, v)
		}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// validateDockerName returns an error if the image name contains unsafe characters.
// Docker image names are of the form: [registry/][namespace/]repository
func validateDockerName(name string) error {
	if name == "" {
		return fmt.Errorf("docker: image name must not be empty")
	}
	// Allow alphanumeric, dash, underscore, dot, slash, colon (for port), and @ for digest refs.
	for _, c := range name {
		if !isDockerNameChar(c) {
			return fmt.Errorf("docker: image name %q contains invalid character %q", name, c)
		}
	}
	// Prevent path traversal.
	if strings.Contains(name, "..") {
		return fmt.Errorf("docker: image name %q contains path traversal sequence", name)
	}
	return nil
}

func isDockerNameChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.' || c == '/' || c == ':' || c == '@'
}
