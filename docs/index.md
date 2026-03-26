# Shieldoo Gate — Documentation

> Open-source supply chain security proxy for Docker, PyPI, npm, NuGet, and more.

## Overview

Shieldoo Gate is a transparent caching proxy that scans every artifact before serving it and blocks delivery of malicious content in real time. Inspired by the LiteLLM/Trivy supply chain incident (March 2026).

## Contents

- [Technical Specification](initial-analyse.md) — full architecture, technology stack, interfaces, and deployment
- [Architecture Decision Records](adr/) — ADRs for key design choices
- [API Reference](api/) — OpenAPI spec for the REST API

## Architecture

```
Client (pip / docker / npm / dotnet)
    │
    ▼
Shieldoo Gate Protocol Adapter
    │
    ├── Cached & clean? → serve immediately
    │
    └── Not cached → download → scan → clean? → cache & serve
                                      → malicious? → block (403)
```

### Core Components

| Component | Description |
|---|---|
| **Protocol Adapters** | Native protocol implementations (Docker/OCI, PyPI PEP 503, npm, NuGet V3) |
| **Scan Engine** | Pluggable scanner framework (GuardDog, Trivy, OSV, built-in heuristics) |
| **Cache Store** | Local filesystem, S3, or Azure Blob storage with TTL |
| **Policy Engine** | Block / quarantine / warn / allow rules with allowlists |
| **Rescan Scheduler** | Periodic rescan of cached artifacts + threat feed updates |
| **Admin UI + REST API** | Dashboard, artifact management, audit log |

## Technology Stack

- **Go 1.25+** — core proxy, API, built-in scanners
- **TypeScript + React 18** — admin UI
- **Python 3.12+** — GuardDog scanner bridge (gRPC sidecar)
- **SQLite** (single-node) / **PostgreSQL** (HA mode)

## Implementation Status (v1.0)

| Phase | Module | Status |
|---|---|---|
| 1 | Skeleton (config, DB, interfaces) | Done |
| 2 | Scanner engine + built-in scanners | Done |
| 3 | External scanners (GuardDog, Trivy, OSV) | Done |
| 4 | Cache & policy engine | Done |
| 5 | Protocol adapters (PyPI, npm, Docker, NuGet) | Done |
| 6 | Admin REST API | Done |
| 7 | Admin UI (React) | Done |
| 8 | Main entrypoint, Docker Compose, E2E tests | Done |

## Getting Started

See the [Quick Start in README](../README.md#quick-start) or the [Deployment section](initial-analyse.md#11-deployment) in the technical specification.

### Example Projects

The [`examples/`](../examples/) directory contains minimal projects (Python, npm, .NET) configured to install dependencies through the local proxy. Each has one dependency and a tiny script — a quick way to verify the proxy works.

### Running with Docker Compose

```bash
# Copy and edit the example config
cp config.example.yaml docker/config.yaml

# Start the full stack (Shieldoo Gate + scanner-bridge)
docker compose -f docker/docker-compose.yml up -d

# Point pip and npm at the proxy
pip config set global.index-url http://localhost:5000/simple/
npm config set registry http://localhost:4873/

# Open the Admin API
curl http://localhost:8080/api/v1/health
```

### Local Development (without Docker)

Prerequisites: Go 1.25+, Node.js 20+, Python 3.12+ with [uv](https://docs.astral.sh/uv/), `protoc` (Protocol Buffers compiler).

```bash
# Generate gRPC code (requires protoc + Go gRPC plugins)
make proto

# Build the binary
make build

# Run with a config file
./bin/shieldoo-gate -config config.example.yaml

# Run tests
make test

# Lint
make lint
```

The scanner bridge must be started separately:

```bash
cd scanner-bridge
uv venv .venv && source .venv/bin/activate
uv pip install -r requirements.txt
python -m bridge.server
```

### Running E2E Tests

```bash
# Start the full stack first (see above), then:
make test-e2e
```

## Contributing

See [Contributing](initial-analyse.md#16-contributing) in the technical specification.
