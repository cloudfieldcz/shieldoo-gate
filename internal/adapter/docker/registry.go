package docker

import (
	"fmt"
	"os"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// RegistryResolver determines the upstream registry for a given image name
// based on the dot-in-first-segment convention and an allowlist.
type RegistryResolver struct {
	defaultUpstream string
	allowed         map[string]registryInfo // host → info
}

type registryInfo struct {
	url  string
	auth *config.DockerRegistryAuth
}

// NewRegistryResolver creates a resolver from config.
func NewRegistryResolver(cfg config.DockerUpstreamConfig) *RegistryResolver {
	allowed := make(map[string]registryInfo, len(cfg.AllowedRegistries))
	for _, r := range cfg.AllowedRegistries {
		allowed[r.Host] = registryInfo{
			url:  strings.TrimRight(r.URL, "/"),
			auth: r.Auth,
		}
	}
	defaultURL := cfg.DefaultRegistry
	if defaultURL == "" {
		defaultURL = "https://registry-1.docker.io"
	}
	return &RegistryResolver{
		defaultUpstream: strings.TrimRight(defaultURL, "/"),
		allowed:         allowed,
	}
}

// Resolve parses an image name and returns (registryHost, imagePath, upstreamURL, error).
//
// Rules:
//   - If the first segment (before first /) contains a dot or colon, it is a registry hostname.
//   - Otherwise the entire name goes to the default registry (Docker Hub).
//   - Bare names without a slash (e.g. "nginx") get "library/" prepended for Docker Hub.
//   - Non-default registries must be in the allowlist, otherwise an error is returned.
func (rr *RegistryResolver) Resolve(name string) (registry, imagePath, upstreamURL string, err error) {
	firstSlash := strings.Index(name, "/")

	if firstSlash > 0 {
		firstSegment := name[:firstSlash]
		if looksLikeRegistry(firstSegment) {
			// First segment is a registry hostname.
			registryHost := firstSegment
			imgPath := name[firstSlash+1:]

			info, ok := rr.allowed[registryHost]
			if !ok {
				return "", "", "", fmt.Errorf("docker: registry %q not in allowed registries", registryHost)
			}
			return registryHost, imgPath, info.url, nil
		}
	}

	// Default registry (Docker Hub).
	imagePath = name
	// Bare name (no slash) → prepend library/ for Docker Hub convention.
	if !strings.Contains(name, "/") {
		imagePath = "library/" + name
	}
	return "docker.io", imagePath, rr.defaultUpstream, nil
}

// looksLikeRegistry returns true if the segment looks like a registry hostname
// (contains a dot or a colon for port).
func looksLikeRegistry(segment string) bool {
	return strings.ContainsAny(segment, ".:")
}

// AuthForRegistry returns the Authorization header value for the given registry,
// or empty string if no auth is configured. Reads token from environment variable.
// SECURITY: Never forward client Authorization headers to upstreams.
func (rr *RegistryResolver) AuthForRegistry(registryHost string) string {
	info, ok := rr.allowed[registryHost]
	if !ok || info.auth == nil || info.auth.TokenEnv == "" {
		return ""
	}
	token := os.Getenv(info.auth.TokenEnv)
	if token == "" {
		return ""
	}
	switch info.auth.Type {
	case "bearer":
		return "Bearer " + token
	case "basic":
		return "Basic " + token
	default:
		return "Bearer " + token
	}
}

// MakeSafeName creates a filesystem/cache-safe name from registry + image path.
// Replaces dots and slashes with underscores. Internal images (registry="") get "_internal" prefix.
func MakeSafeName(registry, imagePath string) string {
	var prefix string
	if registry == "" {
		prefix = "_internal"
	} else {
		prefix = strings.NewReplacer(".", "_", ":", "_").Replace(registry)
	}
	safePath := strings.NewReplacer("/", "_").Replace(imagePath)
	return prefix + "_" + safePath
}
