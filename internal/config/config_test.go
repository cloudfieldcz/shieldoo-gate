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
  docker:
    default_registry: "https://registry-1.docker.io"
    allowed_registries:
      - host: "ghcr.io"
        url: "https://ghcr.io"
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

func TestLoad_DockerUpstreamsMultiRegistry(t *testing.T) {
	yaml := `
server:
  host: "0.0.0.0"
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
  docker:
    default_registry: "https://registry-1.docker.io"
    allowed_registries:
      - host: "ghcr.io"
        url: "https://ghcr.io"
      - host: "quay.io"
        url: "https://quay.io"
    sync:
      enabled: true
      interval: "6h"
      rescan_interval: "24h"
      max_concurrent: 3
    push:
      enabled: true
cache:
  backend: "local"
  local:
    path: "/tmp/test-cache"
    max_size_gb: 1
database:
  backend: "sqlite"
  sqlite:
    path: ":memory:"
scanners:
  timeout: "30s"
policy:
  block_if_verdict: "MALICIOUS"
  quarantine_if_verdict: "SUSPICIOUS"
  minimum_confidence: 0.7
log:
  level: "info"
  format: "json"
`
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(tmpFile, []byte(yaml), 0644))

	cfg, err := Load(tmpFile)
	require.NoError(t, err)

	assert.Equal(t, "https://registry-1.docker.io", cfg.Upstreams.Docker.DefaultRegistry)
	require.Len(t, cfg.Upstreams.Docker.AllowedRegistries, 2)
	assert.Equal(t, "ghcr.io", cfg.Upstreams.Docker.AllowedRegistries[0].Host)
	assert.Equal(t, "https://ghcr.io", cfg.Upstreams.Docker.AllowedRegistries[0].URL)
	assert.True(t, cfg.Upstreams.Docker.Sync.Enabled)
	assert.Equal(t, "6h", cfg.Upstreams.Docker.Sync.Interval)
	assert.Equal(t, 3, cfg.Upstreams.Docker.Sync.MaxConcurrent)
	assert.True(t, cfg.Upstreams.Docker.Push.Enabled)
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

func TestValidate_WebhookEnabledWithoutURL_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = ""
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alerts.webhook.url is required")
}

func TestValidate_WebhookHTTPRejected_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "http://example.com/hook"
	cfg.Alerts.Webhook.AllowInsecure = false
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "https://")
}

func TestValidate_WebhookHTTPAllowedWhenInsecure(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "http://example.com/hook"
	cfg.Alerts.Webhook.AllowInsecure = true
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_WebhookHTTPS_NoError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Webhook.Enabled = true
	cfg.Alerts.Webhook.URL = "https://hooks.example.com/shieldoo"
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_SlackEnabledWithoutWebhookEnv_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Slack.Enabled = true
	cfg.Alerts.Slack.WebhookEnv = ""
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alerts.slack.webhook_env is required")
}

func TestValidate_SlackEnabledWithWebhookEnv_NoError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Slack.Enabled = true
	cfg.Alerts.Slack.WebhookEnv = "SGW_SLACK_WEBHOOK_URL"
	t.Setenv("SGW_SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_EmailEnabledMissingHost_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.Host = ""
	cfg.Alerts.Email.From = "a@b.com"
	cfg.Alerts.Email.To = []string{"c@d.com"}
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alerts.email requires")
}

func TestValidate_EmailEnabledMissingTo_ReturnsError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.Host = "smtp.example.com"
	cfg.Alerts.Email.From = "a@b.com"
	cfg.Alerts.Email.To = nil
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "alerts.email requires")
}

func TestValidate_EmailEnabledComplete_NoError(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Alerts.Email.Enabled = true
	cfg.Alerts.Email.Host = "smtp.example.com"
	cfg.Alerts.Email.From = "a@b.com"
	cfg.Alerts.Email.To = []string{"c@d.com"}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_DisabledAlertsSkipValidation(t *testing.T) {
	cfg := validBaseConfig()
	// All disabled by default — should pass even with empty URLs
	err := cfg.Validate()
	assert.NoError(t, err)
}

// validBaseConfig returns a Config that passes Validate() with all alerts disabled.
func validBaseConfig() *Config {
	return &Config{
		Cache: CacheConfig{
			Backend: "local",
			Local:   LocalCacheConfig{Path: "/tmp/cache"},
		},
		Database: DatabaseConfig{
			Backend: "sqlite",
			SQLite:  SQLiteConfig{Path: "/tmp/gate.db"},
		},
	}
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
