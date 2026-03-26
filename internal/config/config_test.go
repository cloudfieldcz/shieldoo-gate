package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_FromYAML_ParsesAllSections(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`
server:
  host: "127.0.0.1"
ports:
  pypi: 5000
  npm: 4873
  nuget: 5001
  docker: 5002
  admin: 8080
upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
  nuget: "https://api.nuget.org"
  docker: "https://registry-1.docker.io"
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
    max_size_gb: 10
  ttl:
    pypi: "168h"
    npm: "168h"
    nuget: "168h"
    docker: "720h"
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
scanners:
  parallel: true
  timeout: "60s"
  guarddog:
    enabled: true
    bridge_socket: "/tmp/shieldoo-bridge.sock"
  trivy:
    enabled: true
    binary: "trivy"
    cache_dir: "/tmp/trivy-cache"
  osv:
    enabled: true
    api_url: "https://api.osv.dev"
policy:
  block_if_verdict: "MALICIOUS"
  quarantine_if_verdict: "SUSPICIOUS"
  minimum_confidence: 0.7
  allowlist:
    - "pypi:litellm:==1.82.6"
threat_feed:
  enabled: true
  url: "https://feed.shieldoo.io/malicious-packages.json"
  refresh_interval: "1h"
log:
  level: "info"
  format: "json"
`), 0644)
	require.NoError(t, err)

	cfg, err := Load(cfgPath)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 5000, cfg.Ports.PyPI)
	assert.Equal(t, 4873, cfg.Ports.NPM)
	assert.Equal(t, 8080, cfg.Ports.Admin)
	assert.Equal(t, "https://pypi.org", cfg.Upstreams.PyPI)
	assert.Equal(t, "local", cfg.Cache.Backend)
	assert.Equal(t, "/tmp/cache", cfg.Cache.Local.Path)
	assert.Equal(t, "sqlite", cfg.Database.Backend)
	assert.True(t, cfg.Scanners.Parallel)
	assert.Equal(t, "60s", cfg.Scanners.Timeout)
	assert.True(t, cfg.Scanners.GuardDog.Enabled)
	assert.InDelta(t, 0.7, float64(cfg.Policy.MinimumConfidence), 0.001)
	assert.Contains(t, cfg.Policy.Allowlist, "pypi:litellm:==1.82.6")
	assert.True(t, cfg.ThreatFeed.Enabled)
	assert.Equal(t, "info", cfg.Log.Level)
}

func TestLoad_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	err := os.WriteFile(cfgPath, []byte(`
server:
  host: "0.0.0.0"
ports:
  pypi: 5000
  npm: 4873
  nuget: 5001
  docker: 5002
  admin: 8080
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
    max_size_gb: 10
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
log:
  level: "info"
  format: "json"
`), 0644)
	require.NoError(t, err)

	t.Setenv("SGW_LOG_LEVEL", "debug")

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "debug", cfg.Log.Level)
}

func TestValidate_MissingCachePath_ReturnsError(t *testing.T) {
	cfg := &Config{
		Cache: CacheConfig{
			Backend: "local",
			Local:   LocalCacheConfig{Path: ""},
		},
		Database: DatabaseConfig{
			Backend: "sqlite",
			SQLite:  SQLiteConfig{Path: "/tmp/gate.db"},
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cache.local.path")
}

func TestValidate_MissingSQLitePath_ReturnsError(t *testing.T) {
	cfg := &Config{
		Cache: CacheConfig{
			Backend: "local",
			Local:   LocalCacheConfig{Path: "/tmp/cache"},
		},
		Database: DatabaseConfig{
			Backend: "sqlite",
			SQLite:  SQLiteConfig{Path: ""},
		},
	}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database.sqlite.path")
}
