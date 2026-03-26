# Deployment

> How to run Shieldoo Gate with Docker Compose, locally for development, and how to configure clients.

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
| `make lint` | Run `go vet` |
| `make proto` | Regenerate protobuf/gRPC code from `scanner-bridge/proto/scanner.proto` |
| `make clean` | Remove `bin/` directory |

## Testing

### Unit Tests

```bash
make test
```

Runs all Go unit tests excluding the e2e directory.

### E2E Tests (Shell-based)

Full-stack tests that start Docker Compose, install real packages through the proxy, and validate behavior:

```bash
# Start the full stack first
docker compose -f docker/docker-compose.yml up -d

# Run shell-based e2e tests
./tests/e2e-shell/run.sh
```

The `tests/e2e-shell/` directory contains:
- Per-ecosystem test scripts (PyPI, npm, NuGet)
- Fixture files for testing
- Docker Compose stack for isolated testing

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

## Example Projects

The `examples/` directory contains minimal projects pre-configured to use the local proxy:

| Project | Ecosystem | Dependency | Description |
|---|---|---|---|
| `python-requests` | PyPI | `requests` | Python script using requests |
| `npm-chalk` | npm | `chalk` | Node.js script using chalk |
| `dotnet-json` | NuGet | `Newtonsoft.Json` | .NET console app |

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
