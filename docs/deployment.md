# Deployment

> How to run Shieldoo Gate with Docker Compose, Kubernetes (Helm), locally for development, and how to configure clients.

## Docker Compose (Recommended)

The simplest way to run Shieldoo Gate with all components.

### Prerequisites

- Docker and Docker Compose
- A copy of `config.yaml` (start from `config.example.yaml`)

### Quick Start

```bash
# 1. Copy and edit the configuration
cp config.example.yaml docker/config.yaml
# Edit docker/config.yaml as needed

# 2. Start the full stack
docker compose -f docker/docker-compose.yml up -d

# 3. Verify
curl http://localhost:8080/api/v1/health
```

### Docker Compose Architecture

The `docker/docker-compose.yml` defines two services:

```
┌────────────────────┐     Unix socket     ┌────────────────────┐
│  shieldoo-gate     │◀───────────────────▶│  scanner-bridge    │
│  (Go binary)       │   bridge-socket vol  │  (Python/GuardDog) │
│                    │                      │                    │
│  Ports:            │                      │  BRIDGE_SOCKET=    │
│  5010→5000 (PyPI)  │                      │  /tmp/shieldoo-    │
│  4873 (npm)        │                      │  bridge.sock       │
│  5001 (NuGet)      │                      └────────────────────┘
│  5002 (Docker)     │
│  8085 (Maven)      │
│  8086 (RubyGems)   │
│  8087 (Go Modules) │
│  8080 (Admin API)  │
└────────────────────┘
```

**Services:**

| Service | Image | Purpose |
|---|---|---|
| `shieldoo-gate` | Multi-stage build (Node + Go + Trivy + Alpine) | Main proxy, API, and UI. Includes built-in Trivy binary. |
| `scanner-bridge` | Python 3.12-slim + GuardDog + gRPC | GuardDog behavioral scanner sidecar |

**Volumes:**

| Volume | Purpose |
|---|---|
| `bridge-socket` | Shared Unix socket for gRPC communication between Go and Python |
| `gate-data` | SQLite database (`/var/lib/shieldoo-gate/`) |
| `gate-cache` | Cached artifacts (`/var/cache/shieldoo-gate/`) |
| `trivy-cache` | Trivy vulnerability database (`/var/cache/trivy/`) |

**Port mapping:**

| Host | Container | Service |
|---|---|---|
| 5010 | 5000 | PyPI (host port 5010 to avoid macOS AirPlay conflict on 5000) |
| 4873 | 4873 | npm |
| 5001 | 5001 | NuGet |
| 5002 | 5002 | Docker registry |
| 8085 | 8085 | Maven repository |
| 8086 | 8086 | RubyGems |
| 8087 | 8087 | Go module proxy |
| 8080 | 8080 | Admin API + React UI |

### Multi-Stage Dockerfile

The main Dockerfile (`docker/Dockerfile`) uses a multi-stage build:

1. **Node UI builder** — Builds the React admin UI (`npm ci && npm run build`)
2. **Go builder** — Compiles the Go binary with CGO enabled (required for SQLite)
3. **Trivy builder** — Copies the Trivy v0.50.0 binary
4. **Runtime** — Alpine-based image combining all built artifacts

The scanner-bridge has its own Dockerfile (`scanner-bridge/Dockerfile`) that:
1. Installs `uv` for Python package management
2. Installs pinned dependencies from `requirements.txt`
3. Compiles protobuf definitions at build time
4. Runs `python main.py` as the entrypoint

## Local Development (without Docker)

### Prerequisites

- **Go 1.25+** — for building and running the core proxy
- **Node.js 20+** — for building the admin UI
- **Python 3.12+** with [uv](https://docs.astral.sh/uv/) — for the scanner bridge
- **protoc** (Protocol Buffers compiler) — for regenerating gRPC code
- **Trivy** (optional) — install the trivy binary if you want the Trivy scanner

### Build and Run

```bash
# 1. Generate gRPC code (if proto files changed)
make proto

# 2. Build the Go binary
make build
# Output: bin/shieldoo-gate

# 3. Run with example config
./bin/shieldoo-gate -config config.example.yaml
```

### Start the Scanner Bridge (separate terminal)

```bash
cd scanner-bridge
uv venv .venv && source .venv/bin/activate
uv pip install -r requirements.txt
python main.py
```

The bridge listens on the Unix socket configured in `BRIDGE_SOCKET` env var (default `/tmp/shieldoo-bridge.sock`).

### Build the UI (for development)

```bash
cd ui
npm ci
npm run dev    # Vite dev server with hot reload
# or
npm run build  # Production build to dist/
```

### Makefile Targets

| Target | Description |
|---|---|
| `make build` | Build Go binary to `bin/shieldoo-gate` |
| `make test` | Run unit tests (excludes e2e) |
| `make test-e2e` | Run Go e2e tests |
| `make test-e2e-containerized` | Run containerized E2E tests (no host tools needed) |
| `make lint` | Run `go vet` |
| `make proto` | Regenerate protobuf/gRPC code from `scanner-bridge/proto/scanner.proto` |
| `make clean` | Remove `bin/` directory |

## Testing

### Unit Tests

```bash
make test
```

Runs all Go unit tests excluding the e2e directory.

### E2E Tests (Shell-based, host)

Full-stack tests that start Docker Compose, install real packages through the proxy, and validate behavior. Requires host-installed tools: `docker`, `curl`, `jq`, `uv`, `node`, `npm`, `crane`:

```bash
./tests/e2e-shell/run.sh
```

The `tests/e2e-shell/` directory contains:
- Per-ecosystem test scripts (PyPI, npm, NuGet, Docker, Maven, RubyGems, Go Modules)
- Fixture files for testing
- Docker Compose stack for isolated testing

### E2E Tests (Containerized) -- Recommended

Runs all E2E tests inside a Docker container with all package managers pre-installed. No host tools needed beyond Docker. This is the recommended approach for CI/CD and reproducible testing:

```bash
make test-e2e-containerized
```

This builds a test-runner container (`Dockerfile.test-runner`) containing pinned versions of uv, npm, dotnet, Maven, Ruby, Go, and crane. The container connects to shieldoo-gate via Docker networking (no host port mapping needed). Docker-in-Docker (DinD) is used for Docker registry E2E tests.

The test-runner waits for shieldoo-gate to pass its healthcheck, then runs `run_all.sh` which executes all test suites sequentially (including `test_proxy_auth.sh` which is not run by the host-based `run.sh`). The exit code reflects test results (0 = all passed, non-zero = failures).

### Go E2E Tests

```bash
make test-e2e
```

## Client Configuration

### pip / uv (PyPI)

```bash
# pip
pip config set global.index-url http://localhost:5010/simple/

# uv — uv.toml or pyproject.toml
[pip]
index-url = "http://localhost:5010/simple/"

# Per-command
pip install --index-url http://localhost:5010/simple/ requests
uv pip install --index-url http://localhost:5010/simple/ requests
```

### npm / yarn / pnpm

```bash
# npm
npm config set registry http://localhost:4873/

# Per-command
npm install --registry http://localhost:4873/ chalk

# .npmrc (per-project)
registry=http://localhost:4873/
```

### dotnet / NuGet

```bash
# Add source
dotnet nuget add source http://localhost:5001/v3/index.json --name shieldoo-gate

# nuget.config (per-project)
# <add key="shieldoo-gate" value="http://localhost:5001/v3/index.json" />
```

### Docker

```json
// /etc/docker/daemon.json
{
  "registry-mirrors": ["http://localhost:5002"]
}
```

Then restart Docker daemon.

### Maven

```xml
<!-- settings.xml or pom.xml -->
<repositories>
  <repository>
    <id>shieldoo-gate</id>
    <url>http://localhost:8085</url>
  </repository>
</repositories>
```

### RubyGems / Bundler

```bash
# gem
gem install rake --source http://localhost:8086

# Bundler (Gemfile)
source "http://localhost:8086"
```

### Go Modules

```bash
export GOPROXY=http://localhost:8087
go mod download
```

## Example Projects

The `examples/` directory contains minimal projects pre-configured to use the local proxy:

| Project | Ecosystem | Dependency | Description |
|---|---|---|---|
| `python-requests` | PyPI | `requests` | Python script using requests |
| `npm-chalk` | npm | `chalk` | Node.js script using chalk |
| `dotnet-json` | NuGet | `Newtonsoft.Json` | .NET console app |
| `maven-example` | Maven | `commons-lang3` | Java project using Apache Commons |
| `rubygems-example` | RubyGems | `rake` | Ruby project using Rake |
| `go-example` | Go | `golang.org/x/text` | Go module using x/text |

Each example has a README with setup instructions. They are useful for quick verification that the proxy works correctly.

## Admin UI

The React admin UI is served on the admin port (default 8080) as a single-page application. Available pages:

| Route | Description |
|---|---|
| `/dashboard` | Overview with statistics and recent activity |
| `/artifacts` | Browse cached artifacts, view scan results, trigger rescan, quarantine/release |
| `/overrides` | Manage policy overrides (create, revoke) |
| `/audit-log` | View append-only audit log with filtering |
| `/settings` | Configuration viewer |
| `/profile` | User profile and API key management (requires OIDC auth) |

Access it at `http://localhost:8080/` in your browser.

## Prometheus Metrics

Shieldoo Gate exposes Prometheus metrics at `GET /metrics` on the admin port (8080):

```
shieldoo_gate_requests_total{ecosystem, action}       # counter
shieldoo_gate_scan_duration_seconds{scanner}           # histogram
shieldoo_gate_cache_size_bytes{ecosystem}              # gauge
shieldoo_gate_cache_hits_total{ecosystem}              # counter
shieldoo_gate_cache_misses_total{ecosystem}            # counter
shieldoo_gate_blocked_total{ecosystem, reason}         # counter
shieldoo_gate_quarantined_total{ecosystem}             # counter
shieldoo_gate_scanner_errors_total{scanner}            # counter
```

## Security Considerations

- Shieldoo Gate sits in the **critical path** of every dependency installation — treat it as a high-value target
- All scanner dependencies are pinned to **exact versions with hashes** in `requirements.txt`
- The scanner bridge runs as a **separate process** — compromised artifacts cannot escape the scan environment
- The audit log is **append-only** — all decisions are traceable
- Artifact storage encryption at rest is delegated to the storage backend / filesystem

## Kubernetes (Helm Chart)

Shieldoo Gate provides a Helm chart for Kubernetes deployment in `helm/shieldoo-gate/`.

### Quick Start

```bash
# Install with default values (single replica, SQLite, local cache)
helm install shieldoo-gate ./helm/shieldoo-gate/

# Verify
kubectl get pods -l app.kubernetes.io/name=shieldoo-gate
kubectl port-forward svc/shieldoo-gate 8080:8080
curl http://localhost:8080/api/v1/health
```

### HA Setup with PostgreSQL + S3

For production with multiple replicas, you must use PostgreSQL and a shared cache backend (S3, Azure Blob, or GCS). SQLite and local cache do not support multi-replica deployments -- the chart will fail validation if you try.

```bash
# Create a secret with credentials
kubectl create secret generic shieldoo-secrets \
  --from-literal=database-dsn='postgres://user:pass@pghost:5432/shieldoo?sslmode=require' \
  --from-literal=s3-access-key='AKIA...' \
  --from-literal=s3-secret-key='...'

# Install with HA values
helm install shieldoo-gate ./helm/shieldoo-gate/ \
  --set replicaCount=3 \
  --set database.backend=postgres \
  --set cache.backend=s3 \
  --set cache.s3.bucket=shieldoo-cache \
  --set cache.s3.region=us-east-1 \
  --set existingSecret=shieldoo-secrets \
  --set podDisruptionBudget.enabled=true
```

### Ingress Configuration

```yaml
# values-ingress.yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: shieldoo-gate.example.com
      paths:
        - path: /
          pathType: Prefix
          port: admin
  tls:
    - secretName: shieldoo-gate-tls
      hosts:
        - shieldoo-gate.example.com
```

```bash
helm install shieldoo-gate ./helm/shieldoo-gate/ -f values-ingress.yaml
```

### Secret Management

The chart supports two approaches for managing secrets:

1. **Inline secrets** (development only): Set values under `secrets.*` in `values.yaml`. These are base64-encoded into a Kubernetes Secret.

2. **Existing secret** (recommended for production): Create a Kubernetes Secret separately (or via an external secrets operator like External Secrets, Sealed Secrets, or Vault) and reference it with `existingSecret`.

Secret keys used by the chart:

| Key | Purpose |
|---|---|
| `database-dsn` | PostgreSQL connection string |
| `webhook-secret` | Webhook HMAC signing secret |
| `slack-webhook-url` | Slack incoming webhook URL |
| `smtp-username` | SMTP authentication username |
| `smtp-password` | SMTP authentication password |
| `oidc-client-secret` | OIDC client secret for admin auth |
| `s3-access-key` | AWS/S3 access key |
| `s3-secret-key` | AWS/S3 secret key |
| `azure-connection-string` | Azure Storage connection string |

### Image Pinning

For production, use image digests instead of mutable tags:

```yaml
image:
  repository: ghcr.io/cloudfieldcz/shieldoo-gate
  digest: "sha256:abc123..."  # digest takes precedence over tag
```

### Security Features

The chart enforces the following security contexts by default:

- `runAsNonRoot: true` -- containers must run as non-root
- `runAsUser: 1000` -- the `sgw` user
- `readOnlyRootFilesystem: true` -- no writes to container filesystem
- `allowPrivilegeEscalation: false`
- `capabilities.drop: ["ALL"]` -- drop all Linux capabilities
- `automountServiceAccountToken: false` -- no automatic token mount

### Architecture

The Helm chart deploys a Deployment with two containers:

```
Pod
├── shieldoo-gate (main proxy)
│   ├── /etc/shieldoo-gate/config.yaml  (ConfigMap)
│   ├── /data/                           (PVC, SQLite mode)
│   ├── /cache/                          (PVC, local cache mode)
│   ├── /var/run/shieldoo/               (emptyDir, shared socket)
│   └── /var/cache/trivy/                (emptyDir)
└── scanner-bridge (GuardDog sidecar)
    └── /var/run/shieldoo/               (emptyDir, shared socket)
```

The scanner bridge communicates with the main container via a Unix socket at `/var/run/shieldoo/shieldoo-bridge.sock`, mounted from a shared `emptyDir` volume.
