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

- **Go 1.23+** — core proxy, API, built-in scanners
- **TypeScript + React 18** — admin UI
- **Python 3.12+** — GuardDog scanner bridge (gRPC sidecar)
- **SQLite** (single-node) / **PostgreSQL** (HA mode)

## Getting Started

See the [Quick Start in README](../README.md#quick-start) or the [Deployment section](initial-analyse.md#11-deployment) in the technical specification.

## Contributing

See [Contributing](initial-analyse.md#16-contributing) in the technical specification.
