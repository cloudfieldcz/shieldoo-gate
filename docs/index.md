# Shieldoo Gate — Documentation

> Open-source supply chain security proxy for Docker, PyPI, npm, NuGet, Maven, RubyGems, and Go Modules.

## Overview

Shieldoo Gate is a transparent caching proxy that scans every artifact before serving it and blocks delivery of malicious content in real time. Inspired by the LiteLLM/Trivy supply chain incident (March 2026).

## Contents

### Documentation

- [Architecture](architecture.md) — component overview, request flow, startup sequence, concurrency model
- [Data Model](data-model.md) — database schema, Go structs, table relationships, migrations
- [Scanners](scanners.md) — scan engine, built-in and external scanners, aggregation, threat feed
- [Protocol Adapters](adapters.md) — PyPI, npm, NuGet, Docker, Maven, RubyGems, Go Modules proxy implementations and routing
- [Policy Engine](policy.md) — evaluation order, overrides, allowlists, aggregation rules, policy tiers (v1.2), AI triage
- [Configuration](configuration.md) — full `config.yaml` reference, environment variables, Go structs
  - [Authentication](configuration.md#authentication-v11) — OIDC admin API authentication (v1.1)
  - [Alerts](configuration.md#alerts-v11) — webhook, Slack, and email notification channels
- [Deployment](deployment.md) — Docker Compose, Kubernetes (Helm), local development, client configuration, testing

### Reference

- [API Reference](api/) — OpenAPI 3.1 spec for the REST API
- [Planned Features](features/index.md) — phased roadmap with 15 proposed features across enterprise foundation, advanced detection, compliance, developer experience, and advanced deployment

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
| **Protocol Adapters** | Native protocol implementations (Docker/OCI, PyPI PEP 503, npm, NuGet V3, Maven, RubyGems, Go Modules) |
| **Scan Engine** | Pluggable scanner framework (GuardDog, Trivy, OSV, AI/LLM, built-in heuristics, dynamic sandbox) |
| **Cache Store** | Local filesystem, S3/MinIO, Azure Blob Storage, or GCS with per-ecosystem TTL |
| **Policy Engine** | Block / quarantine / warn / allow rules with allowlists and policy tiers (strict/balanced/permissive) |
| **Policy Overrides** | Dynamic false-positive management and audit trail via UI/API |
| **Threat Feed** | Periodic threat feed refresh + manual rescan via API |
| **Rescan Scheduler** | Background re-scanning of cached artifacts to detect newly discovered threats |
| **Alerting** | Real-time notifications via webhook, Slack, and email for security events (v1.1) |
| **Authentication** | OIDC admin API authentication with Authorization Code + PKCE flow (v1.1) |
| **Proxy Auth** | Per-user PAT and global token for proxy endpoint authentication (v1.1) |
| **Admin UI + REST API** | Dashboard, artifact management, audit log, user profile & API key management |

## Technology Stack

- **Go 1.25+** — core proxy, API, built-in scanners
- **TypeScript + React 18** — admin UI
- **Python 3.12+** — GuardDog scanner bridge (gRPC sidecar)
- **SQLite** (default single-node) / **PostgreSQL** (HA mode, v1.1)

## Implementation Status

| Phase | Module | Status |
|---|---|---|
| 1 | Skeleton (config, DB, interfaces) | Done |
| 2 | Scanner engine + built-in scanners | Done |
| 3 | External scanners (GuardDog, Trivy, OSV) | Done |
| 4 | Cache (local) & policy engine | Done |
| 5 | Protocol adapters (PyPI, npm, Docker, NuGet, Maven, RubyGems, Go Modules) | Done |
| 6 | Admin REST API | Done |
| 7 | Admin UI (React) | Done |
| 8 | Main entrypoint, Docker Compose, E2E tests | Done |
| — | Cloud cache backends (S3, Azure Blob, GCS) | Done |
| — | PostgreSQL HA backend | Done |
| — | Docker scheduled sync/rescan | Done |
| — | Helm chart | Done |
| — | Rescan scheduler | Done |
| — | Alerting (webhook, Slack, email) | Done |
| — | OIDC admin authentication | Done |
| — | Proxy API key auth (PAT) | Done |
| — | User profile & API key management UI | Done |
| — | Tag mutability detection | Done |
| — | Dynamic sandbox (gVisor) | Done |
| — | AI Scanner (LLM-based, Azure OpenAI) | Done |
| — | E2E PostgreSQL + MinIO testing | Done |
| — | Typosquatting & namespace confusion detection | Done |
| — | Version diff analysis | Done |
| — | Maintainer reputation risk scoring | Done |

## Getting Started

See the [Quick Start in README](../README.md#quick-start) or the [Deployment guide](deployment.md) for detailed setup instructions.

### Example Projects

The [`examples/`](../examples/) directory contains minimal projects (Python, npm, .NET, Maven, RubyGems, Go) configured to install dependencies through the local proxy. Each has one dependency and a tiny script — a quick way to verify the proxy works.

### Running with Docker Compose

```bash
# Copy and edit the example config
cp config.example.yaml docker/config.yaml

# Start the full stack (Shieldoo Gate + scanner-bridge)
docker compose -f docker/docker-compose.yml up -d

# Point pip and npm at the proxy
pip config set global.index-url http://localhost:5010/simple/
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

# Unit tests
make test

# E2E tests — host-based (requires uv, npm, dotnet, crane, etc.)
./tests/e2e-shell/run.sh

# E2E tests — containerized (recommended, only requires Docker)
make test-e2e-containerized

# Lint
make lint
```

The scanner bridge must be started separately (host-based development only):

```bash
cd scanner-bridge
uv venv .venv && source .venv/bin/activate
uv pip install -r requirements.txt
python main.py
```

### Running E2E Tests

```bash
# Containerized (recommended — no host tools needed beyond Docker)
make test-e2e-containerized

# Host-based (requires all package managers installed locally)
./tests/e2e-shell/run.sh

# Go E2E tests
make test-e2e
```

## Contributing

Shieldoo Gate welcomes contributions under Apache 2.0. See `CONTRIBUTING.md` for guidelines and `SECURITY.md` for responsible disclosure. Threat intelligence contributions (malicious package reports) are especially welcome — submit as OSV-format JSON with evidence.
