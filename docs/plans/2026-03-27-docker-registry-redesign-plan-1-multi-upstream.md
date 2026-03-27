# Docker Registry Redesign — Phase 1: Multi-Upstream Routing + Allowlist

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the Docker adapter to route pull requests to multiple upstream registries based on the first path segment, with an allowlist for permitted registries.

**Architecture:** The first segment of the image name after `/v2/` determines the upstream registry. If it contains a dot (`.`) or colon (`:`), it's treated as a registry hostname and matched against an allowlist. Otherwise, the request goes to the default registry (Docker Hub). The `/v2/` endpoint responds locally instead of proxying. Cache layer keeps existing `_` encoding for safe filesystem paths. A new `docker_repositories` table tracks known repositories. The migration runner gains a `schema_migrations` table for idempotent ALTER TABLE support. Per-registry credentials from config (env var references) — client auth headers are NEVER forwarded to upstreams. Manifest digest is verified against upstream's `Docker-Content-Digest` header.

**Security decisions:**
- Client `Authorization` headers are NOT forwarded to upstreams — Gate authenticates to each upstream independently using per-registry credentials from config
- After fetching a manifest, `sha256(body)` is verified against upstream's `Docker-Content-Digest` header; mismatch → reject
- `EnsureRepository` uses atomic `INSERT OR IGNORE` + `SELECT` to avoid race conditions
- `scanner.Artifact.Name` is set to the safe name (matching `artifactID`) to fix the pre-existing `model.Artifact.ID()` mismatch

**Deferred to Phase 2:**
- `registry` column on `artifacts` table
- Quarantine status migration for existing Docker artifacts

**Tech Stack:** Go 1.25+, chi router, sqlx + SQLite, go-containerregistry/crane, testify

**Index:** [`plan-index.md`](./2026-03-27-docker-registry-redesign-plan-index.md)

---

### Task 1: Config Structs — Replace Docker upstream string with multi-registry struct

**Files:**
- Modify: `internal/config/config.go:34-39`
- Test: `internal/config/config_test.go` (new file or append)

- [ ] **Step 1: Write the failing test**

Create test that loads a YAML config with the new `upstreams.docker` structure:

```go
// internal/config/config_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/config/ -run TestLoad_DockerUpstreamsMultiRegistry -v`
Expected: FAIL — `UpstreamsConfig.Docker` is still a `string`

- [ ] **Step 3: Implement new config structs**

Replace the `Docker string` field in `UpstreamsConfig` with a struct. In `internal/config/config.go`, replace lines 34-39:

```go
type UpstreamsConfig struct {
	PyPI   string             `mapstructure:"pypi"`
	NPM    string             `mapstructure:"npm"`
	NuGet  string             `mapstructure:"nuget"`
	Docker DockerUpstreamConfig `mapstructure:"docker"`
}

type DockerUpstreamConfig struct {
	DefaultRegistry    string                  `mapstructure:"default_registry"`
	AllowedRegistries  []DockerRegistryEntry   `mapstructure:"allowed_registries"`
	Sync               DockerSyncConfig        `mapstructure:"sync"`
	Push               DockerPushConfig        `mapstructure:"push"`
}

type DockerRegistryEntry struct {
	Host string              `mapstructure:"host"`
	URL  string              `mapstructure:"url"`
	Auth *DockerRegistryAuth `mapstructure:"auth"`
}

// DockerRegistryAuth holds per-registry credentials.
// TokenEnv references an environment variable — credentials are NEVER stored in config plaintext.
type DockerRegistryAuth struct {
	Type     string `mapstructure:"type"`      // "bearer" or "basic"
	TokenEnv string `mapstructure:"token_env"` // env var name containing the token/password
}

type DockerSyncConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Interval       string `mapstructure:"interval"`
	RescanInterval string `mapstructure:"rescan_interval"`
	MaxConcurrent  int    `mapstructure:"max_concurrent"`
}

type DockerPushConfig struct {
	Enabled bool `mapstructure:"enabled"`
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/config/ -run TestLoad_DockerUpstreamsMultiRegistry -v`
Expected: PASS

- [ ] **Step 5: Fix existing `TestLoad_FromYAML_ParsesAllSections` test**

The existing config test uses `docker: "https://registry-1.docker.io"` (plain string) which will fail to unmarshal into the new struct. Update the test YAML to use the new structure and update any assertions on `cfg.Upstreams.Docker`.

- [ ] **Step 6: Fix compilation errors in main.go and docker adapter**

Update `cmd/shieldoo-gate/main.go:157` — replace:
```go
dockerUpstream := fallback(cfg.Upstreams.Docker, "https://registry-1.docker.io")
```
with:
```go
dockerDefaultUpstream := cfg.Upstreams.Docker.DefaultRegistry
if dockerDefaultUpstream == "" {
    dockerDefaultUpstream = "https://registry-1.docker.io"
}
```

Update `cmd/shieldoo-gate/main.go:163` — change `NewDockerAdapter` call to pass the whole config:
```go
dockerAdapter := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.Docker)
```

This will break `NewDockerAdapter` signature — fix in Task 2.

- [ ] **Step 7: Update config.example.yaml**

Replace the `docker:` line under `upstreams:` with:
```yaml
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
      enabled: false
```

- [ ] **Step 7: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go config.example.yaml cmd/shieldoo-gate/main.go
git commit -m "feat(config): replace docker upstream string with multi-registry struct"
```

---

### Task 2: Registry Resolver — New `registry.go` with upstream routing logic

**Files:**
- Create: `internal/adapter/docker/registry.go`
- Test: `internal/adapter/docker/registry_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/adapter/docker/registry_test.go
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

func TestMakeSafeName_ReplacesSlashesAndDots(t *testing.T) {
	assert.Equal(t, "ghcr_io_cloudfieldcz_cf-powers", docker.MakeSafeName("ghcr.io", "cloudfieldcz/cf-powers"))
	assert.Equal(t, "docker_io_library_nginx", docker.MakeSafeName("docker.io", "library/nginx"))
	assert.Equal(t, "_internal_myteam_myapp", docker.MakeSafeName("", "myteam/myapp"))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run "TestResolveUpstream|TestMakeSafeName" -v`
Expected: FAIL — package doesn't have these types yet

- [ ] **Step 3: Implement registry.go**

```go
// internal/adapter/docker/registry.go
package docker

import (
	"fmt"
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run "TestResolveUpstream|TestMakeSafeName" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/docker/registry.go internal/adapter/docker/registry_test.go
git commit -m "feat(docker): add multi-upstream registry resolver with allowlist"
```

---

### Task 3: Database Migration — `schema_migrations` tracking + `docker_repositories` table

**Files:**
- Modify: `internal/config/db.go:39-72`
- Create: `internal/config/migrations/003_docker_registry.sql`

- [ ] **Step 1: Write the migration SQL**

```sql
-- internal/config/migrations/003_docker_registry.sql

-- Schema migrations tracking table (run-once semantics for future migrations).
CREATE TABLE IF NOT EXISTS schema_migrations (
    version  INTEGER PRIMARY KEY,
    applied_at DATETIME NOT NULL
);

-- Docker repositories table.
CREATE TABLE IF NOT EXISTS docker_repositories (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    registry       TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,
    is_internal    INTEGER NOT NULL DEFAULT 0,
    created_at     DATETIME NOT NULL,
    last_synced_at DATETIME,
    sync_enabled   INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_docker_repos_registry_name ON docker_repositories(registry, name);
```

- [ ] **Step 2: Write a test for migration idempotency**

```go
// internal/config/db_test.go (append or create)
func TestInitDB_Migration003_Idempotent(t *testing.T) {
	db, err := InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	// Verify docker_repositories table exists
	var count int
	err = db.Get(&count, "SELECT COUNT(*) FROM docker_repositories")
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Run InitDB again (simulates restart) — should not fail
	// We can't re-init :memory:, so just run migrations again manually
	migrations, err := readMigrations()
	require.NoError(t, err)
	for i, sql := range migrations {
		_, err := db.Exec(sql)
		require.NoError(t, err, "migration %d failed on re-run", i+1)
	}
}
```

- [ ] **Step 3: Integrate `schema_migrations` into migration runner**

Modify `internal/config/db.go` — replace the naive "run all migrations" loop with tracked execution:

```go
func InitDB(dbPath string) (*sqlx.DB, error) {
	// ... (open DB, set PRAGMAs — unchanged)

	// Ensure schema_migrations table exists (bootstrap).
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("config: creating schema_migrations: %w", err)
	}

	// Run only unapplied migrations.
	migrations, err := readMigrations()
	if err != nil {
		db.Close()
		return nil, err
	}
	for i, sql := range migrations {
		version := i + 1
		var count int
		_ = db.Get(&count, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version)
		if count > 0 {
			continue // already applied
		}
		if _, err := db.Exec(sql); err != nil {
			db.Close()
			return nil, fmt.Errorf("config: running migration %d: %w", version, err)
		}
		db.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", version, time.Now().UTC())
	}

	return db, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/config/ -run TestInitDB -v`
Expected: PASS (all existing migrations + new 003 run correctly, re-runs are skipped)

- [ ] **Step 5: Commit**

```bash
git add internal/config/migrations/003_docker_registry.sql internal/config/db.go internal/config/db_test.go
git commit -m "feat(db): add docker_repositories table and schema_migrations tracking with run-once semantics"
```

---

### Task 4: Refactor DockerAdapter — Multi-upstream struct + resolver integration

**Files:**
- Modify: `internal/adapter/docker/docker.go:36-64` (struct + constructor)
- Modify: `internal/adapter/docker/docker.go:109-143` (handleV2Check → local response)
- Modify: `internal/adapter/docker/docker.go:151-196` (handleV2Wildcard + handleManifest → use resolver)
- Modify: `internal/adapter/docker/docker.go:283-296` (pullImageToTar → use resolved upstream)
- Modify: `internal/adapter/docker/docker.go:425-457` (fetchManifest → use resolved upstream)
- Modify: `internal/adapter/docker/docker.go:546-577` (proxyUpstream → use resolved upstream)
- Modify: `cmd/shieldoo-gate/main.go:157-163`
- Modify: `internal/adapter/docker/docker_test.go:23-43` (setupTestDocker)

- [ ] **Step 1: Update DockerAdapter struct and constructor**

In `internal/adapter/docker/docker.go`, replace the struct (lines 36-44) and constructor (lines 46-64):

```go
type DockerAdapter struct {
	db         *sqlx.DB
	cache      cache.CacheStore
	scanEngine *scanner.Engine
	policyEng  *policy.Engine
	resolver   *RegistryResolver
	cfg        config.DockerUpstreamConfig
	router     http.Handler
	httpClient *http.Client
}

func NewDockerAdapter(
	db *sqlx.DB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	cfg config.DockerUpstreamConfig,
) *DockerAdapter {
	a := &DockerAdapter{
		db:         db,
		cache:      cacheStore,
		scanEngine: scanEngine,
		policyEng:  policyEngine,
		resolver:   NewRegistryResolver(cfg),
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Minute},
	}
	a.router = a.buildRouter()
	return a
}
```

- [ ] **Step 2: Update handleV2Check to respond locally**

Replace `handleV2Check` (lines 109-143) with a local response:

```go
func (a *DockerAdapter) handleV2Check(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
}
```

- [ ] **Step 3: Update handleV2Wildcard to resolve upstream**

In `handleV2Wildcard` (lines 151-187), after extracting `name`, call the resolver. For manifests, pass registry info to `handleManifest`. For blobs, resolve and pass to `proxyUpstream`.

Replace lines 159-186:
```go
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
		registry, imagePath, upstreamURL, err := a.resolver.Resolve(name)
		if err != nil {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:  "registry not allowed",
				Reason: err.Error(),
			})
			_ = adapter.WriteAuditLog(a.db, model.AuditEntry{
				EventType:  model.EventBlocked,
				ArtifactID: fmt.Sprintf("docker:%s:%s", name, ref),
				ClientIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Reason:     err.Error(),
			})
			return
		}
		a.handleManifest(w, r, registry, imagePath, upstreamURL, ref)

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
		_, imagePath, upstreamURL, err := a.resolver.Resolve(name)
		if err != nil {
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:  "registry not allowed",
				Reason: err.Error(),
			})
			return
		}
		a.proxyUpstream(w, r, upstreamURL, "/v2/"+imagePath+"/blobs/"+digest)

	default:
		http.NotFound(w, r)
	}
```

- [ ] **Step 4: Update handleManifest signature and internals**

Change signature from `(w, r, name, ref)` to `(w, r, registry, imagePath, upstreamURL, ref)`.

Key changes inside `handleManifest`:
- Artifact ID: `safeName := MakeSafeName(registry, imagePath)` + `artifactID := fmt.Sprintf("docker:%s:%s", safeName, ref)`
- Upstream host for crane: derived from `upstreamURL` (strip scheme)
- `fetchManifest` and `proxyUpstream`: pass `upstreamURL` and `registry` explicitly
- `scanner.Artifact.UpstreamURL`: use `upstreamURL + "/v2/" + imagePath + "/manifests/" + ref`
- **IMPORTANT: `scanner.Artifact.Name` must be set to `safeName`** (not `imagePath`) — this ensures `model.Artifact.ID()` matches the manually constructed `artifactID`, fixing the pre-existing ID mismatch bug

- [ ] **Step 5: Update fetchManifest — accept upstreamURL + registry, use per-registry auth, verify digest**

Change signature to accept registry-resolved parameters. SECURITY: Do NOT forward client `Authorization` header. Use per-registry credentials from config via `resolver.AuthForRegistry()`. Verify manifest digest against upstream's `Docker-Content-Digest` header.

```go
func (a *DockerAdapter) fetchManifest(ctx context.Context, r *http.Request, upstreamURL, registryHost, name, ref string) ([]byte, string, error) {
	target := upstreamURL + "/v2/" + name + "/manifests/" + ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: building request: %w", err)
	}

	// Forward Accept header (needed for manifest negotiation).
	if v := r.Header.Get("Accept"); v != "" {
		req.Header.Set("Accept", v)
	}

	// SECURITY: Use per-registry credentials from config, NOT client's Authorization header.
	if auth := a.resolver.AuthForRegistry(registryHost); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("docker: fetch manifest: upstream returned %d", resp.StatusCode)
	}

	const maxManifestSize = 10 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return nil, "", fmt.Errorf("docker: fetch manifest: reading body: %w", err)
	}

	// SECURITY: Verify manifest digest matches upstream's claim.
	if upstreamDigest := resp.Header.Get("Docker-Content-Digest"); upstreamDigest != "" {
		h := sha256.Sum256(body)
		computed := "sha256:" + hex.EncodeToString(h[:])
		if computed != upstreamDigest {
			return nil, "", fmt.Errorf("docker: manifest digest mismatch: computed %s, upstream claims %s", computed, upstreamDigest)
		}
	}

	return body, resp.Header.Get("Content-Type"), nil
}
```

- [ ] **Step 6: Update proxyUpstream to accept upstreamURL + registryHost**

Change signature. SECURITY: Use per-registry credentials, NOT client Authorization header:
```go
func (a *DockerAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, upstreamURL, registryHost, path string) {
	target := upstreamURL + path
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "upstream request error", http.StatusInternalServerError)
		return
	}
	// Forward Accept header only. NEVER forward Authorization from client.
	if v := r.Header.Get("Accept"); v != "" {
		req.Header.Set("Accept", v)
	}
	// Use per-registry credentials from config.
	if auth := a.resolver.AuthForRegistry(registryHost); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	// ... rest stays the same (Do request, copy headers, copy body)
}
```

- [ ] **Step 7: Update HealthCheck to use default upstream**

```go
func (a *DockerAdapter) HealthCheck(ctx context.Context) error {
	defaultURL := a.cfg.DefaultRegistry
	if defaultURL == "" {
		defaultURL = "https://registry-1.docker.io"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultURL+"/v2/", nil)
	// ... rest stays the same
}
```

- [ ] **Step 8: Update main.go to pass config struct**

In `cmd/shieldoo-gate/main.go`, replace lines 157-163:
```go
	// Init all 4 adapters
	pypiAdapter := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, pypiUpstream)
	npmAdapter := npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, npmUpstream)
	nugetAdapter := nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, nugetUpstream)
	dockerAdapter := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.Docker)
```

- [ ] **Step 9: Verify compilation**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go build ./...`
Expected: Compiles without errors

- [ ] **Step 10: Commit**

```bash
git add internal/adapter/docker/docker.go cmd/shieldoo-gate/main.go
git commit -m "refactor(docker): integrate multi-upstream resolver into adapter"
```

---

### Task 5: Update Tests — Fix existing tests for new constructor signature

**Files:**
- Modify: `internal/adapter/docker/docker_test.go:23-85` (setup helper + all tests using old constructor)

- [ ] **Step 1: Update `TestDockerAdapter_V2Check_NoUpstream_StillReturnsHeader`**

This test at line 64-85 directly constructs the adapter with the old string signature. Update to use the new config struct. Since `/v2/` now responds locally, this test can be simplified — upstream unreachability no longer matters:

```go
func TestDockerAdapter_V2Check_NoUpstream_StillReturnsHeader(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "http://does-not-exist.invalid",
	}
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
}
```

- [ ] **Step 2: Update setupTestDocker helper**

Replace the helper (lines 23-43) to use the new config struct:

```go
func setupTestDocker(t *testing.T, upstreamHandler http.HandlerFunc) (*docker.DockerAdapter, *httptest.Server, *sqlx.DB, *local.LocalCacheStore) {
	t.Helper()
	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)

	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: upstream.URL,
	}
	a := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)
	return a, upstream, db, cacheStore
}
```

- [ ] **Step 2: Update artifact ID references in test data**

The artifact ID format changes from `docker:library_alpine:3.20` to `docker:docker_io_library_alpine:3.20` (because `MakeSafeName("docker.io", "library/alpine")` = `docker_io_library_alpine`).

Update `TestDockerAdapter_Manifest_CachedClean_ServesFromCache` (line 109):
```go
artifactID := "docker:docker_io_library_alpine:3.20"
```
And the `Name` field in the `scanner.Artifact`:
```go
Name: "docker_io_library_alpine",
```

Similarly update `TestDockerAdapter_Manifest_QuarantinedImage_Returns403` (line 152):
```go
artifactID := "docker:docker_io_library_malicious:latest"
```
And `Name`:
```go
Name: "docker_io_library_malicious",
```

- [ ] **Step 3: Run all existing tests**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add internal/adapter/docker/docker_test.go
git commit -m "test(docker): update tests for multi-upstream constructor"
```

---

### Task 6: Add tests for disallowed registry and multi-upstream routing

**Files:**
- Modify: `internal/adapter/docker/docker_test.go`

- [ ] **Step 1: Write integration test for disallowed registry**

```go
func TestDockerAdapter_DisallowedRegistry_Returns403(t *testing.T) {
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for disallowed registries")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/evil.io/malware/pkg/manifests/latest", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "not allowed")
}
```

- [ ] **Step 2: Write integration test for allowed non-default registry**

```go
func setupTestDockerMultiUpstream(t *testing.T, defaultHandler, ghcrHandler http.HandlerFunc) *docker.DockerAdapter {
	t.Helper()
	defaultUpstream := httptest.NewServer(defaultHandler)
	t.Cleanup(defaultUpstream.Close)
	ghcrUpstream := httptest.NewServer(ghcrHandler)
	t.Cleanup(ghcrUpstream.Close)

	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, nil)

	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: defaultUpstream.URL,
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: ghcrUpstream.URL},
		},
	}
	return docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg)
}

func TestDockerAdapter_AllowedRegistry_BlobRoutesToCorrectUpstream(t *testing.T) {
	ghcrBlobContent := []byte("ghcr blob data")

	a := setupTestDockerMultiUpstream(t,
		func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("default upstream should not be called for ghcr.io images")
		},
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ghcrBlobContent)
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/v2/ghcr.io/myuser/myapp/blobs/sha256:abc123", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, ghcrBlobContent, w.Body.Bytes())
}
```

- [ ] **Step 3: Write test for bare image name library/ expansion**

```go
func TestDockerAdapter_BareImageName_ExpandsToLibrary(t *testing.T) {
	var receivedPath string
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("blob"))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/nginx/blobs/sha256:abc123", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "/v2/library/nginx/blobs/sha256:abc123", receivedPath)
}
```

- [ ] **Step 4: Run all tests**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/docker/docker_test.go
git commit -m "test(docker): add multi-upstream routing and allowlist tests"
```

---

### Task 7: V2Check test update + full test suite verification

**Files:**
- Modify: `internal/adapter/docker/docker_test.go`

- [ ] **Step 1: Update V2Check tests**

Since `handleV2Check` now responds locally, update `TestDockerAdapter_V2Check_Returns200WithHeader`:

```go
func TestDockerAdapter_V2Check_Returns200WithHeader(t *testing.T) {
	a, _, _, _ := setupTestDocker(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called for /v2/ check")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
}
```

The `TestDockerAdapter_V2Check_NoUpstream_StillReturnsHeader` test can be simplified or removed since we no longer proxy.

- [ ] **Step 2: Run full test suite**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./... -count=1`
Expected: All tests PASS

- [ ] **Step 3: Run linter**

Run: `cd /Users/valda/src/projects/shieldoo-gate && make lint`
Expected: No new warnings

- [ ] **Step 4: Commit**

```bash
git add internal/adapter/docker/docker_test.go
git commit -m "test(docker): update V2Check tests for local response"
```

---

### Task 8: Docker Repositories DB helpers + auto-create on pull

**Files:**
- Create: `internal/adapter/docker/repos.go`
- Create: `internal/adapter/docker/repos_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/adapter/docker/repos_test.go
package docker_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestEnsureRepository_CreatesOnFirstCall(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "ghcr.io", "cloudfieldcz/cf-powers", false)
	require.NoError(t, err)
	assert.Equal(t, "ghcr.io", repo.Registry)
	assert.Equal(t, "cloudfieldcz/cf-powers", repo.Name)
	assert.False(t, repo.IsInternal)
	assert.True(t, repo.ID > 0)
}

func TestEnsureRepository_ReturnsExistingOnSecondCall(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	repo1, err := docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	repo2, err := docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	assert.Equal(t, repo1.ID, repo2.ID)
}

func TestListRepositories_ReturnsAll(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	_, err = docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	_, err = docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	repos, err := docker.ListRepositories(db, "")
	require.NoError(t, err)
	assert.Len(t, repos, 2)
}

func TestListRepositories_FilterByRegistry(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	_, err = docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	_, err = docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	repos, err := docker.ListRepositories(db, "ghcr.io")
	require.NoError(t, err)
	assert.Len(t, repos, 1)
	assert.Equal(t, "ghcr.io", repos[0].Registry)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run "TestEnsureRepository|TestListRepositories" -v`
Expected: FAIL

- [ ] **Step 3: Implement repos.go**

```go
// internal/adapter/docker/repos.go
package docker

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// DockerRepository represents a row in docker_repositories.
type DockerRepository struct {
	ID           int64      `db:"id" json:"id"`
	Registry     string     `db:"registry" json:"registry"`
	Name         string     `db:"name" json:"name"`
	IsInternal   bool       `db:"is_internal" json:"is_internal"`
	CreatedAt    time.Time  `db:"created_at" json:"created_at"`
	LastSyncedAt *time.Time `db:"last_synced_at" json:"last_synced_at,omitempty"`
	SyncEnabled  bool       `db:"sync_enabled" json:"sync_enabled"`
}

// EnsureRepository returns the existing repo or creates a new one.
// SECURITY: Uses atomic INSERT OR IGNORE + SELECT to avoid TOCTOU race conditions
// under concurrent first-access for the same image.
func EnsureRepository(db *sqlx.DB, registry, name string, isInternal bool) (*DockerRepository, error) {
	now := time.Now().UTC()
	// Atomic: INSERT OR IGNORE avoids unique constraint violation under concurrent access.
	_, _ = db.Exec(
		`INSERT OR IGNORE INTO docker_repositories (registry, name, is_internal, created_at, sync_enabled)
		 VALUES (?, ?, ?, ?, ?)`,
		registry, name, isInternal, now, !isInternal,
	)

	// Always SELECT — either we just inserted or the row already existed.
	var repo DockerRepository
	err := db.Get(&repo, "SELECT * FROM docker_repositories WHERE registry = ? AND name = ?", registry, name)
	if err != nil {
		return nil, fmt.Errorf("docker: querying repository: %w", err)
	}
	return &repo, nil
}

// ListRepositories returns all repos, optionally filtered by registry.
func ListRepositories(db *sqlx.DB, registry string) ([]DockerRepository, error) {
	var repos []DockerRepository
	if registry != "" {
		return repos, db.Select(&repos, "SELECT * FROM docker_repositories WHERE registry = ? ORDER BY name", registry)
	}
	return repos, db.Select(&repos, "SELECT * FROM docker_repositories ORDER BY registry, name")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run "TestEnsureRepository|TestListRepositories" -v`
Expected: PASS

- [ ] **Step 5: Integrate EnsureRepository into handleManifest**

In `handleManifest`, after resolving the upstream and before cache check, call:
```go
_, _ = EnsureRepository(a.db, registry, imagePath, false)
```

This is fire-and-forget — repo tracking should not block pulls.

- [ ] **Step 6: Run full test suite**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./... -count=1`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add internal/adapter/docker/repos.go internal/adapter/docker/repos_test.go internal/adapter/docker/docker.go
git commit -m "feat(docker): add docker_repositories DB helpers and auto-create on pull"
```

---

### Task 9: Documentation update

**Files:**
- Modify: `docs/configuration.md` (if exists — update docker upstream config)
- Modify: `docs/adapters.md` (if exists — update Docker adapter section)

- [ ] **Step 1: Update documentation**

Update relevant docs to reflect:
- New `upstreams.docker` config structure (replace single string with struct)
- Multi-upstream routing behavior (dot-in-first-segment convention)
- Allowlist semantics (403 for disallowed registries)
- `library/` prefix auto-expansion for bare image names
- `/v2/` now responds locally
- New `docker_repositories` table

- [ ] **Step 2: Commit**

```bash
git add docs/
git commit -m "docs(docker): update config and adapter docs for multi-upstream support"
```

---

### Task 10: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./... -count=1 -race`
Expected: All PASS, no race conditions

- [ ] **Step 2: Build**

Run: `cd /Users/valda/src/projects/shieldoo-gate && make build`
Expected: Builds successfully

- [ ] **Step 3: Lint**

Run: `cd /Users/valda/src/projects/shieldoo-gate && make lint`
Expected: No new warnings

- [ ] **Step 4: Verify docker compose config**

Check that `docker/config.yaml` (if it exists) is compatible with the new config structure, or update it.

- [ ] **Step 5: Final commit if any remaining changes**

```bash
git status
# If any unstaged changes remain, commit them
```
