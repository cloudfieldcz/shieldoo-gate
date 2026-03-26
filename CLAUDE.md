# CLAUDE.md — Shieldoo Gate

## Project Overview

Shieldoo Gate is an open-source supply chain security proxy for Docker, PyPI, npm, NuGet, and more. It transparently proxies package requests, scans artifacts before serving, and blocks malicious content in real time.

- **Language:** Go 1.25+ (core proxy & API), TypeScript + React (admin UI), Python 3.12+ (scanner bridge)
- **License:** Apache 2.0
- **Status:** Early development (v1.0 in progress)

## Documentation — MANDATORY

**`docs/` is the source of truth for this project. `docs/index.md` is the main entry point.** Documentation is in **English** and must be kept up to date with code changes. All design decisions, architecture, API specs, and development conventions are documented here.

### Rules

1. **Every code change MUST include corresponding documentation updates in `docs/`**
2. If a change affects architecture, API, configuration, or behavior — update the relevant doc
3. New modules/features require a new doc page or section, linked from `docs/index.md`
4. Architecture Decision Records go in `docs/adr/` (format: `ADR-NNN-title.md`)
5. API changes must update `docs/api/openapi.yaml`
6. `README.md` in root is a **lite description only** — it links to `docs/` for details. Do not put detailed documentation in README.md.

## Repository Structure

```
shieldoo-gate/
├── cmd/shieldoo-gate/        # main entrypoint (main.go)
├── internal/
│   ├── adapter/              # protocol adapters (docker/, pypi/, npm/, nuget/)
│   ├── scanner/              # scanner integrations (interface.go, guarddog/, trivy/, osv/)
│   ├── cache/                # storage backends (interface.go, local/, s3/)
│   ├── policy/               # policy engine
│   ├── scheduler/            # rescan scheduler
│   ├── api/                  # REST API handlers
│   ├── model/                # shared data models
│   └── config/               # config loading & validation
├── ui/                       # React admin UI (Vite, TailwindCSS)
├── scanner-bridge/           # Python sidecar for GuardDog (gRPC)
├── helm/                     # Kubernetes Helm chart
├── docker/                   # docker-compose.yml
├── docs/                     # Project documentation (MUST be kept up to date)
│   ├── index.md              # Main documentation entry point
│   ├── adr/                  # Architecture Decision Records
│   └── api/                  # OpenAPI spec
├── tests/
│   ├── integration/
│   └── e2e/
├── Makefile
├── go.mod / go.sum
└── config.example.yaml
```

## Technology Decisions

These are **normative** — do not substitute without creating an ADR in `docs/adr/`.

### Version Pinning — MANDATORY

All component versions MUST be pinned explicitly. No floating or `latest` specifiers.

- **Go:** Pin in `go.mod` (e.g., `go 1.25.x`). Pin all dependencies to exact versions.
- **Python:** Pin in `requirements.txt` with `==` and hashes. Use `uv` for package management.
- **Node/Frontend:** Pin in `package-lock.json`. Use exact versions in `package.json`.
- **Docker base images:** Pin to digest or exact tag (e.g., `python:3.12.x-slim`).
- **CI tools (protoc, trivy, etc.):** Pin to exact version in Makefile or CI config.

### Python Package Manager

Use **`uv`** for all Python package management (scanner-bridge, etc.). Do NOT use pip, poetry, or pipenv directly.

```bash
uv venv .venv
uv pip install -r requirements.txt
uv pip compile requirements.in -o requirements.txt  # to generate pinned deps
```

### Go Dependencies (approved)

- `github.com/go-chi/chi/v5` — HTTP router
- `github.com/spf13/viper` — config (YAML/env)
- `github.com/rs/zerolog` — structured logging (JSON)
- `github.com/jmoiron/sqlx` + `github.com/mattn/go-sqlite3` / `github.com/lib/pq` — database
- `github.com/robfig/cron/v3` — rescan scheduler
- `github.com/google/go-containerregistry` — OCI/Docker registry client
- `github.com/prometheus/client_golang` — metrics
- `github.com/stretchr/testify` — test assertions

### Frontend

React 18 + TypeScript 5.x, Vite, TailwindCSS, TanStack React Query, Recharts, Radix UI, Axios.

### Database

SQLite (default single-node), PostgreSQL (HA mode). Use only ANSI SQL — no vendor extensions.

### Inter-process Communication

Go core <-> Python scanner bridge via gRPC over Unix socket.

## Development Conventions

### Interface Compliance

Before implementing any struct, check `internal/*/interface.go`. Verify with compile-time checks:

```go
var _ scanner.Scanner = (*trivy.TrivyScanner)(nil)
var _ cache.CacheStore = (*s3.S3CacheStore)(nil)
var _ adapter.Adapter = (*pypi.PyPIAdapter)(nil)
```

### Error Handling

- Wrap all errors with context: `fmt.Errorf("trivy scanner: scanning %s: %w", artifact.ID, err)`
- Scanner failures fail open (return `VerdictClean` + log error), never escalate to `MALICIOUS`
- Policy violations return structured errors, never panic

### Testing

Every new function must have a test.

```
unit tests         → internal logic, pure functions, no I/O
integration tests  → real SQLite DB, real filesystem, mock HTTP upstreams
e2e tests          → full stack with docker-compose, real pip/npm/docker clients
```

Test naming: `Test{FunctionName}_{Scenario}_{ExpectedOutcome}`

```go
func TestPyPIAdapter_MaliciousPackage_Returns403(t *testing.T)
func TestTrivyScanner_CleanImage_ReturnsClean(t *testing.T)
```

### Commit Messages

```
feat(pypi): implement PEP 503 proxy adapter
fix(scanner): trivy subprocess timeout not applied
test(npm): add integration test for malicious tarball
docs(adr): ADR-003 use gRPC for scanner bridge
chore(deps): pin trivy to commit abc1234
```

### Task Granularity

Each task should map to **one module**. Do not modify multiple unrelated modules in a single task. Examples:
- Implement one protocol adapter
- Implement one scanner integration
- Implement one storage backend
- Implement REST API endpoint group
- Write integration tests for one adapter

## Security Invariants — NEVER Violate

1. **Never serve a quarantined artifact** — `artifact_status.status == QUARANTINED` is the final gate
2. **Never trust artifact content before scan completes** — scan before cache write
3. **Never log secrets** — scrub Authorization headers, API keys from all log output
4. **Never unpin scanner dependencies** — `requirements.txt` must always use `==` with hashes
5. **Audit log is append-only** — no UPDATE or DELETE on `audit_log` table

## Build & Run

```bash
# Build
make build

# Run tests
make test

# Run locally with Docker Compose
docker compose -f docker/docker-compose.yml up

# Lint
make lint
```
