# Architecture

> How Shieldoo Gate is structured, how components interact, and how requests flow through the system.

## High-Level Overview

Shieldoo Gate runs as a single Go binary that exposes **five HTTP servers** on separate ports — one per supported package ecosystem (PyPI, npm, NuGet, Docker) and one for the Admin API. A Python gRPC sidecar (`scanner-bridge`) provides access to the GuardDog behavioral scanner.

```
                        ┌──────────────────────────────────────────────┐
                        │              Shieldoo Gate (Go)              │
                        │                                              │
  pip/uv ──────:5000──▶ │  ┌────────────┐                              │
  npm/yarn ────:4873──▶ │  │  Protocol   │    ┌──────────────┐         │
  dotnet ──────:5001──▶ │  │  Adapters   │───▶│ Scan Engine  │         │
  docker ──────:5002──▶ │  │ (PyPI, npm, │    │ (parallel,   │         │
                        │  │  NuGet,     │    │  fail-open)  │         │
                        │  │  Docker)    │    └──────┬───────┘         │
                        │  └─────┬──────┘           │                 │
                        │        │            ┌─────▼───────┐         │
                        │        │            │   Policy    │         │
                        │        ▼            │   Engine    │         │
                        │  ┌────────────┐     │ (overrides, │         │
                        │  │   Cache    │     │  allowlist, │         │
                        │  │   Store    │     │  verdicts)  │         │
                        │  │  (local    │     └─────────────┘         │
                        │  │   disk)    │                              │
                        │  └────────────┘     ┌─────────────┐         │
                        │                     │ Threat Feed │         │
  browser ─────:8080──▶ │  ┌────────────┐     │   Client    │         │
                        │  │  Admin API │     │ (periodic   │         │
                        │  │  + React   │     │  refresh)   │         │
                        │  │    UI      │     └─────────────┘         │
                        │  └────────────┘                              │
                        │                     ┌─────────────┐         │
                        │                     │   SQLite    │         │
                        │                     │  Database   │         │
                        │                     └─────────────┘         │
                        └──────────────────────────────────────────────┘
                                       │
                              Unix socket (gRPC)
                                       │
                        ┌──────────────▼───────────────┐
                        │   Scanner Bridge (Python)     │
                        │   GuardDog behavioral scanner │
                        └──────────────────────────────┘
```

## Component Responsibilities

| Component | Package | Responsibility |
|---|---|---|
| **Protocol Adapters** | `internal/adapter/{pypi,npm,nuget,docker}` | Implement native package manager protocols; proxy requests to upstream registries; trigger scan-on-download |
| **Scan Engine** | `internal/scanner/engine.go` | Orchestrate multiple scanners in parallel with timeout; collect results with fail-open semantics |
| **Built-in Scanners** | `internal/scanner/builtin/` | 6 Go-native scanners: hash verifier, install hook analyzer, obfuscation detector, exfil detector, PTH inspector, threat feed checker |
| **External Scanners** | `internal/scanner/{guarddog,trivy,osv}` | Integrations with GuardDog (gRPC), Trivy (subprocess), OSV (HTTP API) |
| **Cache Store** | `internal/cache/local/` | Local filesystem cache with per-ecosystem directory layout |
| **Policy Engine** | `internal/policy/` | Evaluate aggregated scan results against rules; check overrides and allowlists; decide allow/block/quarantine |
| **Threat Feed Client** | `internal/threatfeed/` | Periodically fetch community threat feed and store entries in DB for fast-path lookups |
| **Admin API** | `internal/api/` | REST API for artifact management, audit log, statistics, policy overrides, health checks |
| **Data Models** | `internal/model/` | Shared Go structs for artifacts, scan results, audit entries, overrides, threat feed entries |
| **Configuration** | `internal/config/` | YAML config loading with Viper, environment variable overrides (`SGW_` prefix), DB initialization and migrations |
| **Scanner Bridge** | `scanner-bridge/` | Python gRPC sidecar running GuardDog for PyPI and npm behavioral analysis |

## Request Flow

### First request (cache miss)

```
1. Client sends request (e.g., pip install requests)
       │
2. Protocol Adapter receives request, parses package name + version
       │
3. Adapter checks artifact_status in DB
       │  → QUARANTINED? Return HTTP 403 immediately
       │  → CLEAN and cached? Serve from cache (step 9)
       │
4. Adapter downloads artifact from upstream registry
       │
5. Scan Engine runs all applicable scanners in parallel
       │  Each scanner gets a context with timeout (default 60s)
       │  Scanner errors → VerdictClean (fail-open)
       │
6. Policy Engine evaluates aggregated results:
       │  a. Check DB overrides (highest priority)
       │  b. Check static allowlist
       │  c. Apply verdict rules (MALICIOUS → block, SUSPICIOUS → quarantine)
       │
7. Based on policy decision:
       │  → ALLOW: Store in cache, set status CLEAN, serve to client
       │  → BLOCK: Return HTTP 403, log BLOCKED event
       │  → QUARANTINE: Store but don't serve, set status QUARANTINED, return 403
       │
8. Write scan results to scan_results table
       │
9. Write audit log entry (SERVED or BLOCKED)
```

### Subsequent requests (cache hit)

```
1. Client sends request
       │
2. Adapter checks artifact_status in DB
       │  → CLEAN? Serve from local cache immediately
       │  → QUARANTINED? Return HTTP 403
       │
3. Update last_accessed_at timestamp
       │
4. Write SERVED audit log entry
```

## Startup Sequence

The main entrypoint (`cmd/shieldoo-gate/main.go`) initializes components in this order:

1. **Parse config** — Read YAML config file (`-config` flag, default `config.yaml`), apply `SGW_*` environment overrides
2. **Validate config** — Check required fields (cache path, DB path)
3. **Setup logger** — Configure zerolog level and format (JSON or text)
4. **Initialize database** — Open SQLite, run embedded migrations (`001_init.sql`, `002_policy_overrides.sql`), set WAL mode and foreign keys
5. **Initialize cache store** — Create local filesystem cache at configured path
6. **Register scanners** — Always register 6 built-in scanners; conditionally add GuardDog, Trivy, OSV based on config
7. **Create scan engine** — Wrap all scanners with parallel execution and timeout
8. **Create policy engine** — Parse allowlist entries, connect to DB for override lookups
9. **Start threat feed client** — Background goroutine: initial refresh + periodic ticker
10. **Create 4 protocol adapters** — Each receives DB, cache, scan engine, policy engine, upstream URL
11. **Create admin API server** — Receives DB, cache, scan engine, policy engine
12. **Launch 5 HTTP servers** — Using `errgroup` for concurrent lifecycle management
13. **Wait for shutdown signal** — SIGINT/SIGTERM triggers graceful shutdown (15s timeout)

## Inter-Process Communication

The Go core communicates with the Python scanner bridge via **gRPC over a Unix socket** (`/tmp/shieldoo-bridge.sock` by default). The protocol is defined in `scanner-bridge/proto/scanner.proto`:

- `ScanArtifact(ScanRequest) → ScanResponse` — Send artifact path + metadata, receive verdict + findings
- `HealthCheck(HealthRequest) → HealthResponse` — Liveness check

The bridge runs as a separate process (separate container in Docker Compose). The shared socket is mounted as a volume.

## Concurrency Model

- **Scanner Engine** runs all applicable scanners in parallel using goroutines + `sync.WaitGroup`. A single `context.WithTimeout` applies to the entire scan batch.
- **HTTP servers** run concurrently via `errgroup`. Each ecosystem adapter and the admin API run on their own port.
- **Threat feed refresh** runs in a background goroutine with `time.Ticker`.
- **Graceful shutdown** propagates via context cancellation + `http.Server.Shutdown()` with a 15-second deadline.

## Security Architecture

See also: [Policy Engine](policy.md)

1. **Scan-before-serve** — Artifacts are never served before scanning completes. The cache write happens only after policy evaluation returns ALLOW.
2. **Fail-open scanners** — Individual scanner failures produce `VerdictClean` with the error logged. This prevents scanner outages from blocking all package installations.
3. **Quarantine is final** — Once `artifact_status.status = QUARANTINED`, the artifact is never served regardless of policy engine state. The `IsServable()` method on `ArtifactStatus` enforces this.
4. **Append-only audit log** — No UPDATE or DELETE operations on the `audit_log` table. Every decision is traceable.
5. **Input validation** — Package names and versions are validated against `^[a-zA-Z0-9._\-]+$` to prevent path traversal and injection.
6. **No secret logging** — Authorization headers and API keys are scrubbed from log output.
