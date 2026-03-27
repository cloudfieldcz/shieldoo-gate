package docker_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestResolveUpstream_DefaultRegistry_NoPrefix(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
	}
	r := docker.NewRegistryResolver(cfg)

	registry, imagePath, upstreamURL, err := r.Resolve("library/nginx")
	require.NoError(t, err)
	assert.Equal(t, "docker.io", registry)
	assert.Equal(t, "library/nginx", imagePath)
	assert.Equal(t, "https://registry-1.docker.io", upstreamURL)
}

func TestResolveUpstream_BareImageName_AddsLibraryPrefix(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
	}
	r := docker.NewRegistryResolver(cfg)

	registry, imagePath, upstreamURL, err := r.Resolve("nginx")
	require.NoError(t, err)
	assert.Equal(t, "docker.io", registry)
	assert.Equal(t, "library/nginx", imagePath)
	assert.Equal(t, "https://registry-1.docker.io", upstreamURL)
}

func TestResolveUpstream_AllowedRegistry_WithDot(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: "https://ghcr.io"},
		},
	}
	r := docker.NewRegistryResolver(cfg)

	registry, imagePath, upstreamURL, err := r.Resolve("ghcr.io/cloudfieldcz/cf-powers")
	require.NoError(t, err)
	assert.Equal(t, "ghcr.io", registry)
	assert.Equal(t, "cloudfieldcz/cf-powers", imagePath)
	assert.Equal(t, "https://ghcr.io", upstreamURL)
}

func TestResolveUpstream_RegistryWithPort(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "myregistry.corp:5000", URL: "https://myregistry.corp:5000"},
		},
	}
	r := docker.NewRegistryResolver(cfg)

	registry, imagePath, upstreamURL, err := r.Resolve("myregistry.corp:5000/team/app")
	require.NoError(t, err)
	assert.Equal(t, "myregistry.corp:5000", registry)
	assert.Equal(t, "team/app", imagePath)
	assert.Equal(t, "https://myregistry.corp:5000", upstreamURL)
}

func TestResolveUpstream_DisallowedRegistry_Returns403(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: "https://ghcr.io"},
		},
	}
	r := docker.NewRegistryResolver(cfg)

	_, _, _, err := r.Resolve("evil.io/malware/pkg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowed registries")
}

func TestResolveUpstream_DockerHubWithSlash_NoFalsePositive(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
	}
	r := docker.NewRegistryResolver(cfg)

	// "myuser/myimage" has no dot in first segment → goes to default
	registry, imagePath, _, err := r.Resolve("myuser/myimage")
	require.NoError(t, err)
	assert.Equal(t, "docker.io", registry)
	assert.Equal(t, "myuser/myimage", imagePath)
}

func TestRegistryResolver_IsPushAllowed_InternalNamespace(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: "https://ghcr.io"},
		},
		Push: config.DockerPushConfig{Enabled: true},
	}
	r := docker.NewRegistryResolver(cfg)

	// Internal namespace (has slash, no dot in first segment) → push allowed
	assert.True(t, r.IsPushAllowed("myteam/myapp"))

	// Upstream registry namespace → push forbidden
	assert.False(t, r.IsPushAllowed("ghcr.io/user/app"))

	// Bare name (no slash) → would go to docker hub library/ → push forbidden
	assert.False(t, r.IsPushAllowed("nginx"))

	// Note: "library/nginx" has a slash and "library" has no dot, so it
	// is treated as an internal namespace (same as "myteam/myapp").
	// Docker Hub's library/ convention is a pull-side concept only.
	assert.True(t, r.IsPushAllowed("library/nginx"))
}

func TestRegistryResolver_IsPushAllowed_MultiLevelInternal(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		Push:            config.DockerPushConfig{Enabled: true},
	}
	r := docker.NewRegistryResolver(cfg)

	// Multi-level internal namespace
	assert.True(t, r.IsPushAllowed("myteam/subteam/myapp"))
}

func TestMakeSafeName_ReplacesSlashesAndDots(t *testing.T) {
	assert.Equal(t, "ghcr_io_cloudfieldcz_cf-powers", docker.MakeSafeName("ghcr.io", "cloudfieldcz/cf-powers"))
	assert.Equal(t, "docker_io_library_nginx", docker.MakeSafeName("docker.io", "library/nginx"))
	assert.Equal(t, "_internal_myteam_myapp", docker.MakeSafeName("", "myteam/myapp"))
}
