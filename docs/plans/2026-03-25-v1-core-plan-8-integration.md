# Shieldoo Gate v1.0 Core — Phase 8: Main Entrypoint + Docker Compose + E2E Tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire all components together in the main entrypoint, create Docker build and compose files, write E2E tests with real package manager clients, and update documentation.

**Architecture:** The main entrypoint uses `errgroup.Group` to manage 5 HTTP servers (PyPI:5000, npm:4873, NuGet:5001, Docker:5002, Admin:8080) with graceful shutdown. Docker multi-stage build for Go+UI. Docker Compose runs shieldoo-gate + scanner-bridge with a shared Unix socket volume. E2E tests use real `pip`, `npm`, `docker`, and `dotnet` clients against the running stack.

**Tech Stack:** Go 1.25+, errgroup, Docker, docker-compose, testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: Complete Main Entrypoint

**Files:**
- Modify: `cmd/shieldoo-gate/main.go`

- [ ] **Step 1: Write test for main initialization**

Create a simple test that verifies config loading and DB initialization work together:

```go
// cmd/shieldoo-gate/main_test.go
package main

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/config"
    "github.com/stretchr/testify/require"
)

func TestMain_ConfigAndDBInit(t *testing.T) {
    dir := t.TempDir()
    cfgPath := filepath.Join(dir, "config.yaml")
    dbPath := filepath.Join(dir, "test.db")
    cachePath := filepath.Join(dir, "cache")

    err := os.WriteFile(cfgPath, []byte(`
server:
  host: "127.0.0.1"
ports:
  pypi: 15000
  npm: 14873
  nuget: 15001
  docker: 15002
  admin: 18080
cache:
  backend: "local"
  local:
    path: "`+cachePath+`"
    max_size_gb: 1
database:
  backend: "sqlite"
  sqlite:
    path: "`+dbPath+`"
scanners:
  parallel: true
  timeout: "10s"
log:
  level: "debug"
  format: "text"
`), 0644)
    require.NoError(t, err)

    cfg, err := config.Load(cfgPath)
    require.NoError(t, err)
    require.NoError(t, cfg.Validate())

    db, err := config.InitDB(cfg.Database.SQLite.Path)
    require.NoError(t, err)
    defer db.Close()
}
```

- [ ] **Step 2: Implement complete main.go with DI and multi-port listener**

Replace the skeleton from Phase 1 with the full implementation:

```go
// cmd/shieldoo-gate/main.go
package main

import (
    "context"
    "flag"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
    "golang.org/x/sync/errgroup"

    "github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
    "github.com/cloudfieldcz/shieldoo-gate/internal/adapter/npm"
    "github.com/cloudfieldcz/shieldoo-gate/internal/adapter/nuget"
    "github.com/cloudfieldcz/shieldoo-gate/internal/adapter/pypi"
    "github.com/cloudfieldcz/shieldoo-gate/internal/api"
    "github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
    "github.com/cloudfieldcz/shieldoo-gate/internal/config"
    "github.com/cloudfieldcz/shieldoo-gate/internal/policy"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/osv"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/trivy"
    "github.com/cloudfieldcz/shieldoo-gate/internal/threatfeed"
)

func main() {
    configPath := flag.String("config", "config.yaml", "path to configuration file")
    flag.Parse()

    // Load config
    cfg, err := config.Load(*configPath)
    if err != nil {
        log.Fatal().Err(err).Msg("failed to load config")
    }
    if err := cfg.Validate(); err != nil {
        log.Fatal().Err(err).Msg("invalid config")
    }

    // Setup logger
    level, _ := zerolog.ParseLevel(cfg.Log.Level)
    zerolog.SetGlobalLevel(level)
    if cfg.Log.Format == "text" {
        log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
    }

    // Init database
    db, err := config.InitDB(cfg.Database.SQLite.Path)
    if err != nil {
        log.Fatal().Err(err).Msg("failed to initialize database")
    }
    defer db.Close()

    // Init cache
    cacheStore, err := local.NewLocalCacheStore(cfg.Cache.Local.Path, cfg.Cache.Local.MaxSizeGB)
    if err != nil {
        log.Fatal().Err(err).Msg("failed to initialize cache")
    }

    // Init scanners
    var scanners []scanner.Scanner

    // Built-in scanners (always enabled)
    scanners = append(scanners,
        builtin.NewPTHInspector(),
        builtin.NewInstallHookAnalyzer(),
        builtin.NewObfuscationDetector(),
        builtin.NewExfilDetector(),
        builtin.NewHashVerifier(),
        builtin.NewThreatFeedChecker(db),
    )

    // External scanners (conditionally enabled)
    if cfg.Scanners.GuardDog.Enabled {
        gd, err := guarddog.NewGuardDogScanner(cfg.Scanners.GuardDog.BridgeSocket)
        if err != nil {
            log.Warn().Err(err).Msg("GuardDog scanner not available")
        } else {
            scanners = append(scanners, gd)
        }
    }
    if cfg.Scanners.Trivy.Enabled {
        timeout, _ := time.ParseDuration(cfg.Scanners.Timeout)
        scanners = append(scanners, trivy.NewTrivyScanner(
            cfg.Scanners.Trivy.Binary, cfg.Scanners.Trivy.CacheDir, timeout))
    }
    if cfg.Scanners.OSV.Enabled {
        timeout, _ := time.ParseDuration(cfg.Scanners.Timeout)
        scanners = append(scanners, osv.NewOSVScanner(cfg.Scanners.OSV.APIURL, timeout))
    }

    scanTimeout, _ := time.ParseDuration(cfg.Scanners.Timeout)
    scanEngine := scanner.NewEngine(scanners, scanTimeout)

    // Init policy engine
    policyEngine := policy.NewEngine(policy.EngineConfig{
        BlockIfVerdict:      cfg.Policy.BlockIfVerdict,
        QuarantineIfVerdict: cfg.Policy.QuarantineIfVerdict,
        MinimumConfidence:   cfg.Policy.MinimumConfidence,
        Allowlist:           cfg.Policy.Allowlist,
    })

    // Init threat feed (initial refresh + periodic refresh)
    if cfg.ThreatFeed.Enabled {
        feedClient := threatfeed.NewClient(db, cfg.ThreatFeed.URL)
        if err := feedClient.Refresh(context.Background()); err != nil {
            log.Warn().Err(err).Msg("initial threat feed refresh failed")
        }
        // Start periodic refresh goroutine
        refreshInterval, _ := time.ParseDuration(cfg.ThreatFeed.RefreshInterval)
        if refreshInterval == 0 {
            refreshInterval = 1 * time.Hour
        }
        go func() {
            ticker := time.NewTicker(refreshInterval)
            defer ticker.Stop()
            for {
                select {
                case <-ctx.Done():
                    return
                case <-ticker.C:
                    if err := feedClient.Refresh(context.Background()); err != nil {
                        log.Warn().Err(err).Msg("threat feed refresh failed")
                    } else {
                        log.Info().Msg("threat feed refreshed")
                    }
                }
            }
        }()
    }

    // Init adapters
    pypiAdapter := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.PyPI)
    npmAdapter := npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.NPM)
    dockerAdapter := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.Docker)
    nugetAdapter := nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.NuGet)

    // Init admin API
    apiServer := api.NewServer(db, cacheStore, scanEngine, policyEngine)

    // Graceful shutdown context
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        sig := <-sigCh
        log.Info().Str("signal", sig.String()).Msg("shutting down")
        cancel()
    }()

    // Start multi-port HTTP servers
    g, gCtx := errgroup.WithContext(ctx)

    servers := []struct {
        name    string
        addr    string
        handler http.Handler
    }{
        {"pypi", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Ports.PyPI), pypiAdapter},
        {"npm", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Ports.NPM), npmAdapter},
        {"docker", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Ports.Docker), dockerAdapter},
        {"nuget", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Ports.NuGet), nugetAdapter},
        {"admin", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Ports.Admin), apiServer.Routes()},
    }

    for _, s := range servers {
        srv := &http.Server{Addr: s.addr, Handler: s.handler}
        name := s.name
        g.Go(func() error {
            log.Info().Str("service", name).Str("addr", srv.Addr).Msg("listening")
            if err := srv.ListenAndServe(); err != http.ErrServerClosed {
                return fmt.Errorf("%s server error: %w", name, err)
            }
            return nil
        })
        g.Go(func() error {
            <-gCtx.Done()
            shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
            defer shutdownCancel()
            return srv.Shutdown(shutdownCtx)
        })
    }

    log.Info().Msg("shieldoo-gate started")
    if err := g.Wait(); err != nil {
        log.Error().Err(err).Msg("server error")
    }
    log.Info().Msg("shieldoo-gate stopped")
}
```

- [ ] **Step 3: Add errgroup dependency**

```bash
go get golang.org/x/sync@latest
```

- [ ] **Step 4: Verify build**

Run: `make build`
Expected: Binary builds successfully.

- [ ] **Step 5: Commit**

```bash
git add cmd/shieldoo-gate/ go.mod go.sum
git commit -m "feat: complete main entrypoint with DI, multi-port listener, graceful shutdown"
```

---

### Task 2: Dockerfile (Multi-stage Build)

**Files:**
- Create: `docker/Dockerfile`

- [ ] **Step 1: Create multi-stage Dockerfile**

```dockerfile
# docker/Dockerfile

# Stage 1: Build UI
FROM node:20-alpine AS ui-builder
WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.23-alpine AS go-builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui-builder /app/ui/dist ./ui/dist
RUN CGO_ENABLED=1 go build -o /bin/shieldoo-gate ./cmd/shieldoo-gate

# Stage 3: Runtime
FROM alpine:3.19
RUN apk add --no-cache ca-certificates sqlite-libs
COPY --from=go-builder /bin/shieldoo-gate /usr/local/bin/
COPY config.example.yaml /etc/shieldoo-gate/config.yaml

RUN mkdir -p /var/cache/shieldoo-gate /var/lib/shieldoo-gate

EXPOSE 5000 4873 5001 5002 8080

ENTRYPOINT ["shieldoo-gate"]
CMD ["--config", "/etc/shieldoo-gate/config.yaml"]
```

- [ ] **Step 2: Verify Docker build**

Run: `docker build -f docker/Dockerfile -t shieldoo-gate:dev .`
Expected: Image builds successfully.

- [ ] **Step 3: Commit**

```bash
git add docker/Dockerfile
git commit -m "chore(docker): add multi-stage Dockerfile for Go backend + React UI"
```

---

### Task 3: Docker Compose

**Files:**
- Create: `docker/docker-compose.yml`

- [ ] **Step 1: Create docker-compose.yml**

Based on `docs/initial-analyse.md` section 11.1, with scanner-bridge sidecar:

```yaml
# docker/docker-compose.yml
services:
  shieldoo-gate:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    ports:
      - "5000:5000"    # PyPI
      - "4873:4873"    # npm
      - "5001:5001"    # NuGet
      - "5002:5002"    # Docker
      - "8080:8080"    # Admin + API
    volumes:
      - ../config.example.yaml:/etc/shieldoo-gate/config.yaml
      - gate-cache:/var/cache/shieldoo-gate
      - gate-data:/var/lib/shieldoo-gate
      - bridge-socket:/tmp
    environment:
      - SGW_LOG_LEVEL=info
    depends_on:
      scanner-bridge:
        condition: service_healthy
    restart: unless-stopped

  scanner-bridge:
    build:
      context: ../scanner-bridge
      dockerfile: Dockerfile
    volumes:
      - bridge-socket:/tmp
    environment:
      - BRIDGE_SOCKET=/tmp/shieldoo-bridge.sock
    healthcheck:
      test: ["CMD", "python", "-c", "import os; assert os.path.exists('/tmp/shieldoo-bridge.sock')"]
      interval: 5s
      timeout: 3s
      retries: 5
    restart: unless-stopped

volumes:
  gate-cache:
  gate-data:
  bridge-socket:
```

- [ ] **Step 2: Verify compose starts**

Run: `docker compose -f docker/docker-compose.yml up --build -d`
Expected: Both services start and are healthy.

- [ ] **Step 3: Commit**

```bash
git add docker/docker-compose.yml
git commit -m "chore(docker): add docker-compose.yml with shieldoo-gate + scanner-bridge"
```

---

### Task 4: E2E Tests

**Files:**
- Create: `tests/e2e/e2e_test.go`

E2E tests require a running docker-compose stack. These tests use real package manager commands.

- [ ] **Step 1: Write E2E test suite**

```go
// tests/e2e/e2e_test.go
//go:build e2e

package e2e

import (
    "encoding/json"
    "net/http"
    "os/exec"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

const (
    pypiURL  = "http://localhost:5000"
    npmURL   = "http://localhost:4873"
    adminURL = "http://localhost:8080"
)

func TestE2E_HealthEndpoint(t *testing.T) {
    resp, err := http.Get(adminURL + "/api/v1/health")
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var health map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&health)
    assert.Contains(t, []string{"ok", "degraded"}, health["status"])
}

func TestE2E_PyPI_InstallCleanPackage(t *testing.T) {
    cmd := exec.Command("pip", "install", "--index-url", pypiURL+"/simple/", "--no-deps", "--target", t.TempDir(), "six")
    output, err := cmd.CombinedOutput()
    require.NoError(t, err, "pip install failed: %s", string(output))
}

func TestE2E_NPM_InstallCleanPackage(t *testing.T) {
    dir := t.TempDir()
    cmd := exec.Command("npm", "install", "--registry", npmURL+"/", "--prefix", dir, "is-odd")
    output, err := cmd.CombinedOutput()
    require.NoError(t, err, "npm install failed: %s", string(output))
}

func TestE2E_Admin_ListArtifacts(t *testing.T) {
    // Wait for artifacts from previous tests to be indexed
    time.Sleep(2 * time.Second)

    resp, err := http.Get(adminURL + "/api/v1/artifacts")
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestE2E_Admin_StatsSummary(t *testing.T) {
    resp, err := http.Get(adminURL + "/api/v1/stats/summary")
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestE2E_Metrics_Endpoint(t *testing.T) {
    resp, err := http.Get(adminURL + "/metrics")
    require.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain")
}
```

- [ ] **Step 2: Add e2e test target to Makefile**

```makefile
test-e2e:
	go test -tags e2e ./tests/e2e/ -v -timeout 300s
```

- [ ] **Step 3: Run E2E tests**

Run: `docker compose -f docker/docker-compose.yml up -d && make test-e2e`
Expected: All E2E tests PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/ Makefile
git commit -m "test(e2e): add end-to-end tests with real pip, npm clients"
```

---

### Task 5: Documentation Update

**Files:**
- Modify: `docs/index.md`
- Modify: `README.md`

- [ ] **Step 1: Update docs/index.md**

Add links to the implementation plans and any new documentation created during implementation.

- [ ] **Step 2: Update README.md Quick Start**

Add working Quick Start instructions that reference docker-compose:

```markdown
## Quick Start

```bash
# Clone and start
git clone https://github.com/cloudfieldcz/shieldoo-gate.git
cd shieldoo-gate
docker compose -f docker/docker-compose.yml up -d

# Configure pip to use Shieldoo Gate
pip config set global.index-url http://localhost:5000/simple/

# Configure npm
npm config set registry http://localhost:4873/

# Install a package — it will be scanned transparently
pip install requests

# Check the admin dashboard
open http://localhost:8080
```
```

- [ ] **Step 3: Commit**

```bash
git add docs/index.md README.md
git commit -m "docs: update index and README with Quick Start instructions"
```

---

### Task 6: Final Verification

- [ ] **Step 1: Run all unit tests**

Run: `make test`
Expected: All PASS.

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: No issues.

- [ ] **Step 3: Build binary**

Run: `make build`
Expected: Binary at `bin/shieldoo-gate`.

- [ ] **Step 4: Docker compose up and verify all services healthy**

Run:
```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps
```
Expected: All services healthy.

- [ ] **Step 5: Smoke test with real clients**

```bash
pip install --index-url http://localhost:5000/simple/ requests
npm install --registry http://localhost:4873/ lodash
curl http://localhost:8080/api/v1/health
curl http://localhost:8080/metrics
```
Expected: All commands succeed.
