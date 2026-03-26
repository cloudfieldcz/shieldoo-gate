# Shieldoo Gate — Technical Specification

> Open source supply chain security proxy for Docker, PyPI, npm, NuGet and more.

**Project:** `shieldoo-gate`  
**GitHub:** `github.com/cloudfieldcz/shieldoo-gate`  
**License:** Apache 2.0  
**Status:** Draft v0.2 — March 2026  
**Inspired by:** LiteLLM/Trivy supply chain incident (TeamPCP, March 2026)

---

## 1. Motivation

In March 2026, threat actor TeamPCP compromised the Trivy security scanner's CI/CD pipeline, stole PyPI publishing credentials, and distributed malicious versions of LiteLLM — a Python package downloaded ~95 million times per month. The malicious `.pth` file executed on every Python interpreter startup and exfiltrated SSH keys, cloud credentials, and environment variables.

The attack vector was simple: no tool existed that would **transparently proxy package requests, scan the artifact before serving it to the developer or CI pipeline, and block delivery of malicious content in real time**.

Commercial solutions (Sonatype Nexus Firewall, JFrog Curation) solve this problem but are expensive and closed source. Harbor solves it for Docker images only. Nothing exists for PyPI, npm, NuGet, or Maven in a unified, open source form.

**Shieldoo Gate fills this gap.**

---

## 2. Goals

- Act as a **transparent caching proxy** for all major package ecosystems
- **Scan every artifact** before it is served or cached
- **Block delivery** of artifacts that fail security checks
- **Periodically rescan** the cache and flag or quarantine newly-discovered threats
- Be **self-hostable** with a single Docker Compose or Helm chart
- Be **ecosystem-agnostic** — one tool, one config, multiple package managers
- Stay **100% open source** under Apache 2.0

### Non-goals (v1.0)

- License compliance enforcement (future)
- SBOM generation (future)
- Malware removal / patching
- Authentication / authorization beyond upstream credentials

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       Shieldoo Gate                         │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │  Protocol    │   │  Scan Engine │   │  Cache Store   │  │
│  │  Adapters    │──▶│  (pluggable) │──▶│  (local/S3/    │  │
│  │              │   │              │   │   Azure Blob)  │  │
│  │  - Docker    │   │  - GuardDog  │   └────────────────┘  │
│  │  - PyPI      │   │  - Trivy     │                        │
│  │  - npm       │   │  - OSV       │   ┌────────────────┐  │
│  │  - NuGet     │   │  - custom    │   │  Policy Engine │  │
│  │  - Maven     │   └──────────────┘   │                │  │
│  │  - RubyGems  │                      │  block/warn/   │  │
│  └──────────────┘                      │  quarantine    │  │
│                                        └────────────────┘  │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │  Rescan Job  │   │  Admin UI    │   │  Audit Log     │  │
│  │  (scheduler) │   │  + REST API  │   │  + Alerts      │  │
│  └──────────────┘   └──────────────┘   └────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Request flow

```
Client (pip / docker / npm / dotnet)
    │
    │  GET /simple/litellm/          ← standard package manager protocol
    ▼
Shieldoo Gate Protocol Adapter
    │
    ├── Is artifact in cache AND scan result CLEAN AND not expired?
    │       └── YES → serve from cache immediately
    │
    └── NO → download from upstream registry
              │
              ▼
         Scan Engine
              │
         ┌────┴────────────────────────┐
         │ CLEAN                       │ MALICIOUS / POLICY FAIL
         ▼                             ▼
    Store in cache              Quarantine artifact
    Serve to client             Return 403 + reason
    Log: ALLOWED                Log: BLOCKED + IoCs
```

---

## 4. Technology Stack

This section is **normative** — AI agents implementing Shieldoo Gate must use exactly these technologies and versions unless a later ADR overrides a specific choice. Consistency is more important than perfection; do not substitute alternatives without creating an ADR.

### 4.1 Language & Runtime

| Component | Technology | Version | Rationale |
|---|---|---|---|
| Core proxy & API | **Go** | 1.23+ | High-performance HTTP, excellent TLS, low memory, strong stdlib, easy cross-compilation |
| Admin UI | **TypeScript + React** | TS 5.x, React 18 | Type safety critical for complex state; broad ecosystem |
| Scanner bridge | **Python** | 3.12+ | GuardDog is Python-native; runs as sidecar process |

### 4.2 Repository Structure

```
shieldoo-gate/
├── cmd/
│   └── shieldoo-gate/        # main entrypoint
│       └── main.go
├── internal/
│   ├── adapter/              # protocol adapters (one subpackage per ecosystem)
│   │   ├── docker/
│   │   ├── pypi/
│   │   ├── npm/
│   │   └── nuget/
│   ├── scanner/              # scanner integrations
│   │   ├── interface.go      # Scanner interface definition
│   │   ├── guarddog/
│   │   ├── trivy/
│   │   └── osv/
│   ├── cache/                # storage backends
│   │   ├── interface.go
│   │   ├── local/
│   │   └── s3/
│   ├── policy/               # policy engine
│   ├── scheduler/            # rescan scheduler
│   ├── api/                  # REST API handlers
│   ├── model/                # shared data models
│   └── config/               # config loading & validation
├── ui/                       # React admin UI
│   ├── src/
│   ├── package.json
│   └── tsconfig.json
├── scanner-bridge/           # Python sidecar for GuardDog
│   ├── main.py
│   └── requirements.txt      # ALL deps pinned to exact hashes
├── helm/                     # Kubernetes Helm chart
├── docker/
│   └── docker-compose.yml
├── docs/
│   ├── adr/                  # Architecture Decision Records
│   └── api/                  # OpenAPI spec
├── tests/
│   ├── integration/
│   └── e2e/
├── Makefile
├── go.mod
├── go.sum
└── config.example.yaml
```

### 4.3 Go Dependencies

All Go dependencies pinned in `go.sum`. Approved direct dependencies:

| Package | Purpose |
|---|---|
| `github.com/go-chi/chi/v5` | HTTP router — lightweight, idiomatic |
| `github.com/spf13/viper` | Config file loading (YAML/env) |
| `github.com/rs/zerolog` | Structured logging (JSON output) |
| `github.com/jmoiron/sqlx` | SQL query helpers |
| `github.com/mattn/go-sqlite3` | SQLite driver (CGO) for single-node |
| `github.com/lib/pq` | PostgreSQL driver for HA mode |
| `github.com/robfig/cron/v3` | Rescan scheduler (cron expressions) |
| `github.com/google/go-containerregistry` | OCI/Docker registry client |
| `github.com/opencontainers/image-spec` | OCI image spec types |
| `github.com/prometheus/client_golang` | Prometheus metrics |
| `github.com/stretchr/testify` | Test assertions |
| `gopkg.in/yaml.v3` | YAML config parsing |

### 4.4 Python Scanner Bridge Dependencies

`scanner-bridge/requirements.txt` — ALL pinned with `==` and `--hash`:

```
guarddog==0.1.17 \
    --hash=sha256:...
semgrep==1.62.0 \
    --hash=sha256:...
grpcio==1.62.0 \
    --hash=sha256:...
```

> ⚠️ **Never use floating version specifiers in the scanner bridge.** We do not repeat the Trivy mistake.

### 4.5 Frontend Dependencies

```json
{
  "dependencies": {
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "react-router-dom": "6.23.1",
    "@tanstack/react-query": "5.40.0",
    "recharts": "2.12.7",
    "lucide-react": "0.383.0",
    "@radix-ui/react-dialog": "1.1.1",
    "tailwindcss": "3.4.4",
    "axios": "1.7.2"
  },
  "devDependencies": {
    "typescript": "5.5.2",
    "vite": "5.3.1",
    "@types/react": "18.3.3",
    "vitest": "1.6.0"
  }
}
```

### 4.6 Database Schema

SQLite for single-node (default), PostgreSQL for HA (`--db-backend postgres`). Schema is identical — use only ANSI SQL features, no vendor extensions.

```sql
-- Cached artifacts
CREATE TABLE artifacts (
    id              TEXT PRIMARY KEY,     -- "{ecosystem}:{name}:{version}"
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    upstream_url    TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    cached_at       DATETIME NOT NULL,
    last_accessed_at DATETIME NOT NULL,
    storage_path    TEXT NOT NULL
);

-- Scan results (one per artifact per scanner run)
CREATE TABLE scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id     TEXT NOT NULL REFERENCES artifacts(id),
    scanned_at      DATETIME NOT NULL,
    scanner_name    TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    verdict         TEXT NOT NULL,        -- CLEAN | SUSPICIOUS | MALICIOUS
    confidence      REAL NOT NULL,
    findings_json   TEXT NOT NULL,        -- JSON array of Finding objects
    duration_ms     INTEGER NOT NULL
);

-- Current status (denormalized for fast lookup)
CREATE TABLE artifact_status (
    artifact_id     TEXT PRIMARY KEY REFERENCES artifacts(id),
    status          TEXT NOT NULL,        -- CLEAN | SUSPICIOUS | QUARANTINED | PENDING_SCAN
    quarantine_reason TEXT,
    quarantined_at  DATETIME,
    released_at     DATETIME,
    rescan_due_at   DATETIME NOT NULL,
    last_scan_id    INTEGER REFERENCES scan_results(id)
);

-- Immutable audit log
CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              DATETIME NOT NULL,
    event_type      TEXT NOT NULL,        -- SERVED | BLOCKED | QUARANTINED | RELEASED | SCANNED
    artifact_id     TEXT,
    client_ip       TEXT,
    user_agent      TEXT,
    reason          TEXT,
    metadata_json   TEXT
);

-- Community threat feed entries
CREATE TABLE threat_feed (
    sha256          TEXT PRIMARY KEY,
    ecosystem       TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    version         TEXT,
    reported_at     DATETIME NOT NULL,
    source_url      TEXT,
    iocs_json       TEXT
);

CREATE INDEX idx_artifacts_ecosystem_name ON artifacts(ecosystem, name);
CREATE INDEX idx_scan_results_artifact ON scan_results(artifact_id);
CREATE INDEX idx_audit_log_ts ON audit_log(ts);
CREATE INDEX idx_threat_feed_ecosystem ON threat_feed(ecosystem, package_name);
```

### 4.7 Inter-process Communication

The Go core communicates with the Python scanner bridge via **gRPC** over a Unix socket (same pod/container):

```protobuf
// scanner-bridge/proto/scanner.proto
syntax = "proto3";
package scanner;

service ScannerBridge {
    rpc ScanArtifact(ScanRequest) returns (ScanResponse);
    rpc HealthCheck(HealthRequest) returns (HealthResponse);
}

message ScanRequest {
    string artifact_path = 1;   // local path to downloaded artifact
    string ecosystem = 2;        // pypi | npm | docker | nuget | maven
    string package_name = 3;
    string version = 4;
}

message ScanResponse {
    string verdict = 1;          // CLEAN | SUSPICIOUS | MALICIOUS
    float confidence = 2;
    repeated Finding findings = 3;
    string scanner_version = 4;
    int64 duration_ms = 5;
}

message Finding {
    string severity = 1;         // INFO | LOW | MEDIUM | HIGH | CRITICAL
    string category = 2;
    string description = 3;
    string location = 4;
    repeated string iocs = 5;
}
```

### 4.8 Core Go Interfaces

AI agents must implement against these interfaces. Do not change interface signatures without an ADR.

```go
// internal/scanner/interface.go

type Ecosystem string

const (
    EcosystemPyPI   Ecosystem = "pypi"
    EcosystemNPM    Ecosystem = "npm"
    EcosystemDocker Ecosystem = "docker"
    EcosystemNuGet  Ecosystem = "nuget"
    EcosystemMaven  Ecosystem = "maven"
)

type Verdict string

const (
    VerdictClean      Verdict = "CLEAN"
    VerdictSuspicious Verdict = "SUSPICIOUS"
    VerdictMalicious  Verdict = "MALICIOUS"
)

type Severity string

const (
    SeverityInfo     Severity = "INFO"
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)

type Artifact struct {
    ID          string
    Ecosystem   Ecosystem
    Name        string
    Version     string
    LocalPath   string    // path to downloaded artifact on disk
    SHA256      string
    SizeBytes   int64
    UpstreamURL string
}

type Finding struct {
    Severity    Severity
    Category    string
    Description string
    Location    string
    IoCs        []string
}

type ScanResult struct {
    Verdict    Verdict
    Confidence float32    // 0.0–1.0
    Findings   []Finding
    ScannerID  string
    Duration   time.Duration
    ScannedAt  time.Time
    Error      error      // non-nil if scanner failed (does not imply MALICIOUS)
}

type Scanner interface {
    Name() string
    Version() string
    SupportedEcosystems() []Ecosystem
    Scan(ctx context.Context, artifact Artifact) (ScanResult, error)
    HealthCheck(ctx context.Context) error
}
```

```go
// internal/cache/interface.go

type CacheStore interface {
    // Get returns the local path to a cached artifact, or ErrNotFound
    Get(ctx context.Context, artifactID string) (localPath string, err error)

    // Put stores an artifact from localPath and returns its SHA256
    Put(ctx context.Context, artifact Artifact, localPath string) error

    // Delete removes an artifact from cache
    Delete(ctx context.Context, artifactID string) error

    // List returns artifact IDs matching the filter
    List(ctx context.Context, filter CacheFilter) ([]string, error)

    // Stats returns cache usage statistics
    Stats(ctx context.Context) (CacheStats, error)
}

var ErrNotFound = errors.New("artifact not found in cache")
```

```go
// internal/adapter/interface.go

type Adapter interface {
    Ecosystem() Ecosystem
    // ServeHTTP implements the native protocol of the package registry
    ServeHTTP(w http.ResponseWriter, r *http.Request)
    // HealthCheck verifies upstream connectivity
    HealthCheck(ctx context.Context) error
}
```

### 4.9 Configuration File

```yaml
# config.yaml — complete reference

server:
  host: "0.0.0.0"
  tls:
    enabled: false
    cert_file: ""
    key_file: ""

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
  docker: "https://registry-1.docker.io"

cache:
  backend: "local"           # local | s3 | azureblob
  local:
    path: "/var/cache/shieldoo-gate"
    max_size_gb: 50
  s3:
    bucket: ""
    region: ""
    endpoint: ""             # for MinIO / custom S3
  azure_blob:
    account_name: ""
    container_name: ""
  ttl:
    pypi: "168h"             # 7 days
    npm: "168h"
    nuget: "168h"
    docker: "720h"           # 30 days

database:
  backend: "sqlite"          # sqlite | postgres
  sqlite:
    path: "/var/lib/shieldoo-gate/gate.db"
  postgres:
    dsn: ""

scanners:
  parallel: true
  timeout: "60s"
  guarddog:
    enabled: true
    bridge_socket: "/tmp/shieldoo-bridge.sock"
  trivy:
    enabled: true
    binary: "trivy"
    cache_dir: "/var/cache/trivy"
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

rescan:
  enabled: true
  schedule: "0 2 * * *"
  on_feed_update: true

alerts:
  slack:
    enabled: false
    webhook_url: ""
    on: ["BLOCKED", "QUARANTINED"]
  webhook:
    enabled: false
    url: ""
    on: ["ALL"]

log:
  level: "info"              # debug | info | warn | error
  format: "json"             # json | text
```

---

## 5. Protocol Adapters

Each adapter implements the native protocol so **zero client-side configuration** is needed beyond pointing the package manager at Shieldoo Gate's URL.

### 5.1 Docker / OCI

- Implements [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) v1.1
- Uses `github.com/google/go-containerregistry` for upstream communication
- Proxies Docker Hub, GHCR, MCR, Quay, and custom registries
- Scans image layers using Trivy (CVE) + obfuscation detector
- Manifest list / multi-arch support

**Routing:**
```
GET  /v2/                          → version check
GET  /v2/{name}/manifests/{ref}    → pull manifest (triggers scan if not cached)
GET  /v2/{name}/blobs/{digest}     → pull layer blob
POST /v2/{name}/blobs/uploads/     → push (to hosted registry)
```

### 5.2 PyPI

- Implements [PEP 503](https://peps.python.org/pep-0503/) Simple Repository API
- Implements [PEP 691](https://peps.python.org/pep-0691/) JSON API
- Detects `.pth` files, `exec(base64.decode(...))`, suspicious `setup.py` hooks
- Compatible with `pip`, `uv`, `poetry`, `pdm`

**Routing:**
```
GET  /simple/                      → package index
GET  /simple/{package}/            → package file list
GET  /packages/{path}              → download artifact (triggers scan)
```

### 5.3 npm

- Implements npm Registry API
- Scans `postinstall` scripts, obfuscated JS, network calls at install time
- Compatible with `npm`, `yarn`, `pnpm`

**Routing:**
```
GET  /{package}                    → package metadata
GET  /{package}/{version}          → version metadata
GET  /{package}/-/{tarball}        → download tarball (triggers scan)
```

### 5.4 NuGet

- Implements [NuGet V3 API](https://learn.microsoft.com/en-us/nuget/api/overview)
- Compatible with `dotnet`, `nuget.exe`, Visual Studio, MSBuild

**Routing:**
```
GET  /v3/index.json                → service index
GET  /v3/registration/{id}/index   → package metadata
GET  /v3-flatcontainer/{id}/{v}    → download .nupkg (triggers scan)
```

### 5.5 Maven *(v1.1)*

- Implements Maven repository HTTP layout
- Compatible with Maven, Gradle

### 5.6 RubyGems *(v1.1)*

- Implements [RubyGems API](https://guides.rubygems.org/rubygems-org-api/)
- Compatible with `gem`, Bundler

---

## 6. Scan Engine

### 6.1 Built-in scanners

| Scanner | Ecosystems | What it detects |
|---|---|---|
| **GuardDog** (Datadog, via bridge) | PyPI, npm | Behavioral heuristics, obfuscation, exfiltration, compromised maintainer accounts |
| **Trivy** (binary subprocess) | Docker, all | CVEs, misconfigurations, secrets in layers |
| **OSV Scanner** (API) | PyPI, npm, Maven, Go | Known vulnerabilities from OSV/NVD/GitHub Advisory DB |
| **PTH Inspector** (built-in Go) | PyPI | `.pth` files with executable code — exact LiteLLM attack vector |
| **Install Hook Analyzer** (built-in Go) | PyPI, npm | Suspicious `setup.py`, `postinstall` scripts |
| **Obfuscation Detector** (built-in Go) | All | `base64.decode(exec(...))`, packed JS, encrypted blobs |
| **Exfil Detector** (built-in Go) | All | HTTP calls to non-registry domains at install time |
| **Hash Verifier** (built-in Go) | All | Artifact hash vs upstream + SLSA provenance if available |
| **Threat Feed Checker** (built-in Go) | All | Fast-path lookup against community feed (SHA256) |

### 6.2 Scan result aggregation

```go
// internal/policy/aggregator.go

func Aggregate(results []scanner.ScanResult, cfg AggregationConfig) AggregatedResult {
    // 1. Fast path: threat feed hit → immediate MALICIOUS regardless of confidence
    // 2. Any scanner reports MALICIOUS with confidence >= cfg.MinConfidence → MALICIOUS
    // 3. Any scanner reports SUSPICIOUS with confidence >= cfg.MinConfidence → SUSPICIOUS
    // 4. All scanners CLEAN or error → CLEAN (errors are logged but do not escalate)
}
```

### 6.3 Community threat feed

Shieldoo Gate maintains a public feed of confirmed malicious package hashes in OSV format:

```
https://feed.shieldoo.io/malicious-packages.json
```

Format (OSV-compatible):
```json
{
  "schema_version": "1.0",
  "updated": "2026-03-25T10:00:00Z",
  "entries": [
    {
      "sha256": "abc123...",
      "ecosystem": "pypi",
      "package": "litellm",
      "versions": ["1.82.7", "1.82.8"],
      "reported_at": "2026-03-24T12:00:00Z",
      "source": "https://github.com/shieldoo/shieldoo-gate/issues/1",
      "iocs": [
        "models.litellm.cloud",
        "~/.config/sysmon/sysmon.py"
      ]
    }
  ]
}
```

---

## 7. Cache Store

### 7.1 Storage layout (local backend)

```
/var/cache/shieldoo-gate/
├── pypi/
│   └── litellm/
│       └── 1.82.6/
│           └── litellm-1.82.6-py3-none-any.whl   ← artifact file
├── npm/
├── docker/
│   └── library/
│       └── python/
│           └── sha256_abc123...                   ← image layer blob
└── nuget/
```

### 7.2 Cache metadata

Stored in database `artifact_status` table. Key fields:

```go
type ArtifactStatus struct {
    ArtifactID      string
    Status          Status        // CLEAN | SUSPICIOUS | QUARANTINED | PENDING_SCAN
    QuarantineReason string
    RescanDueAt     time.Time
    LastScanID      int64
}
```

---

## 8. Rescan Scheduler

```go
// internal/scheduler/rescan.go

type RescanScheduler struct {
    cron     *cron.Cron
    db       *sqlx.DB
    scanner  scanner.Engine
    policy   *policy.Engine
    alerter  alert.Alerter
}

// Priority queue for rescan:
// 1. Artifacts whose RescanDueAt has passed
// 2. Ordered by last_accessed_at DESC (most used first)
// 3. Batch size: 100 artifacts per run
```

When a cached artifact is reclassified as MALICIOUS after rescan:
1. Artifact moved to quarantine (file renamed to `.quarantine`, not deleted)
2. `artifact_status.status` set to `QUARANTINED`
3. Alert fired via all configured channels
4. Subsequent requests return `HTTP 403` with JSON error body:

```json
{
  "error": "artifact_quarantined",
  "artifact": "pypi:litellm:1.82.6",
  "reason": "Reclassified as MALICIOUS during scheduled rescan",
  "quarantined_at": "2026-03-25T02:15:00Z",
  "details_url": "http://shieldoo-gate:8080/api/v1/artifacts/pypi:litellm:1.82.6"
}
```

---

## 9. Policy Engine

```yaml
# Policy evaluation order: first matching rule wins

policies:
  - name: "allowlist-pinned"
    condition:
      artifact_in: ["pypi:litellm:==1.82.6"]
    action: allow

  - name: "block-malicious"
    condition:
      verdict: "MALICIOUS"
    action: block

  - name: "quarantine-suspicious-pypi"
    condition:
      ecosystem: "pypi"
      verdict: "SUSPICIOUS"
    action: quarantine

  - name: "warn-high-cve"
    condition:
      finding_severity_gte: "HIGH"
    action: warn

  - name: "default-allow"
    condition: {}
    action: allow
```

Policy actions:
- `allow` — serve artifact, log `SERVED`
- `block` — return HTTP 403, log `BLOCKED`, optionally alert
- `quarantine` — store artifact but do not serve, log `QUARANTINED`, alert
- `warn` — serve artifact, log `WARNED`, optionally alert

---

## 10. REST API

OpenAPI 3.1 spec in `docs/api/openapi.yaml`. Key endpoints:

```
# Artifact management
GET    /api/v1/artifacts                        list cached artifacts (pagination, filter)
GET    /api/v1/artifacts/{id}                   artifact detail + scan history
GET    /api/v1/artifacts/{id}/scan-results      scan result history
POST   /api/v1/artifacts/{id}/rescan            trigger manual rescan
POST   /api/v1/artifacts/{id}/quarantine        manual quarantine
POST   /api/v1/artifacts/{id}/release           release from quarantine

# Audit log
GET    /api/v1/audit                            paginated audit log (filter by event_type)

# Statistics
GET    /api/v1/stats/summary                    traffic summary (last 24h, 7d, 30d)
GET    /api/v1/stats/blocked                    blocked artifacts history

# Threat feed
GET    /api/v1/feed                             local copy of community feed
POST   /api/v1/feed/refresh                     force feed refresh

# System
GET    /api/v1/health                           health + scanner status
GET    /metrics                                 Prometheus metrics
```

### Prometheus metrics

```
shieldoo_gate_requests_total{ecosystem, action}          counter
shieldoo_gate_scan_duration_seconds{scanner}             histogram
shieldoo_gate_cache_size_bytes{ecosystem}                gauge
shieldoo_gate_cache_hits_total{ecosystem}                counter
shieldoo_gate_cache_misses_total{ecosystem}              counter
shieldoo_gate_blocked_total{ecosystem, reason}           counter
shieldoo_gate_quarantined_total{ecosystem}               counter
shieldoo_gate_scanner_errors_total{scanner}              counter
```

---

## 11. Deployment

### 11.1 Docker Compose (quickstart)

```yaml
version: "3.9"
services:
  shieldoo-gate:
    image: ghcr.io/shieldoo/shieldoo-gate:latest
    ports:
      - "5000:5000"    # PyPI
      - "4873:4873"    # npm
      - "5001:5001"    # NuGet
      - "5002:5002"    # Docker registry
      - "8080:8080"    # Admin UI + REST API
    volumes:
      - ./config.yaml:/etc/shieldoo-gate/config.yaml
      - gate-cache:/var/cache/shieldoo-gate
      - gate-data:/var/lib/shieldoo-gate
    environment:
      - SGW_LOG_LEVEL=info

volumes:
  gate-cache:
  gate-data:
```

### 11.2 Kubernetes / Helm

```bash
helm repo add shieldoo https://charts.shieldoo.io
helm install shieldoo-gate shieldoo/shieldoo-gate \
  --set cache.backend=azureblob \
  --set cache.azureBlob.accountName=myaccount \
  --set cache.azureBlob.containerName=shieldoo-cache \
  --set ingress.enabled=true
```

### 11.3 Client configuration

```bash
# pip
pip config set global.index-url http://shieldoo-gate:5000/simple/

# npm
npm config set registry http://shieldoo-gate:4873/

# dotnet / NuGet
dotnet nuget add source http://shieldoo-gate:5001/v3/index.json --name shieldoo-gate

# Docker — /etc/docker/daemon.json
{ "registry-mirrors": ["http://shieldoo-gate:5002"] }

# uv — uv.toml
[pip]
index-url = "http://shieldoo-gate:5000/simple/"
```

---

## 12. AI Agent Development Guidelines

This section describes conventions for AI coding agents (Claude Code and similar) implementing Shieldoo Gate.

### 12.1 Task decomposition

Each development task should map to **one module** in the repository structure. Agents must not modify multiple unrelated modules in a single task. Suggested task granularity:

- Implement one protocol adapter (e.g. PyPI adapter)
- Implement one scanner integration (e.g. Trivy scanner)
- Implement one storage backend (e.g. S3 cache)
- Implement REST API endpoint group
- Write integration tests for one adapter

### 12.2 Interface compliance

Before implementing any struct, the agent must check `internal/*/interface.go` and implement the defined interface exactly. Verify with:

```bash
# Go will error at compile time if interface is not satisfied
var _ scanner.Scanner = (*trivy.TrivyScanner)(nil)
var _ cache.CacheStore = (*s3.S3CacheStore)(nil)
var _ adapter.Adapter = (*pypi.PyPIAdapter)(nil)
```

### 12.3 Error handling conventions

```go
// All errors must be wrapped with context:
return nil, fmt.Errorf("trivy scanner: scanning %s: %w", artifact.ID, err)

// Scanner failures must NOT escalate to MALICIOUS:
if err != nil {
    return ScanResult{
        Verdict:   VerdictClean,   // fail open, log the error
        ScannerID: s.Name(),
        Error:     err,
    }, nil
}

// Policy violations must return structured errors, never panic
```

### 12.4 Testing requirements

Every new function must have a test. Required test types:

```
unit tests         → internal logic, pure functions, no I/O
integration tests  → real SQLite DB, real filesystem, mock HTTP upstreams
e2e tests          → full stack with docker-compose, real pip/npm/docker clients
```

Test naming convention:
```go
func Test{FunctionName}_{Scenario}_{ExpectedOutcome}(t *testing.T)
// e.g.:
func TestPyPIAdapter_MaliciousPackage_Returns403(t *testing.T)
func TestTrivyScanner_CleanImage_ReturnsClean(t *testing.T)
```

### 12.5 Commit conventions

```
feat(pypi): implement PEP 503 proxy adapter
fix(scanner): trivy subprocess timeout not applied
test(npm): add integration test for malicious tarball
docs(adr): ADR-003 use gRPC for scanner bridge
chore(deps): pin trivy to commit abc1234
```

### 12.6 Security invariants — never violate

1. **Never serve a quarantined artifact** — even if policy engine has a bug, `artifact_status.status == QUARANTINED` is the final gate
2. **Never trust artifact content before scan completes** — scan before cache write, not after
3. **Never log secrets** — scrub Authorization headers, API keys from all log output
4. **Never unpin scanner dependencies** — `requirements.txt` must always use `==` with hashes
5. **Audit log is append-only** — no UPDATE or DELETE on `audit_log` table

---

## 13. Security Considerations

- Shieldoo Gate itself is a **high-value target** — it sits in the critical path of every dependency installation
- All scanner dependencies pinned to **exact commit hashes** in CI
- Scanners run in **isolated containers** — malicious artifacts cannot escape scan environment
- Admin UI protected by authentication (local users or OIDC/SAML)
- Artifact storage encrypted at rest (delegated to storage backend)
- Audit log is **append-only** — all decisions traceable
- Regular automated security scans of Shieldoo Gate itself (dogfooding)
- SLSA Level 2 build provenance for all releases

---

## 14. Limitations & Known Gaps (v1.0)

- **Behavioral sandbox** — static analysis only in v1.0; dynamic sandbox (executing install scripts in isolation) deferred to v1.1
- **Zero-day window** — gap between a new malicious package and feed update; behavioral heuristics reduce but cannot eliminate this
- **Encrypted payloads** — sufficiently sophisticated obfuscation may evade static analysis (litellm 1.82.8 used double-base64); runtime sandbox would help
- **Performance** — first-time requests slower due to scanning; warm cache responses are fast
- **Go modules proxy** — deferred to v1.1 (complex module authentication)

---

## 15. Roadmap

### v1.0 — Core
- PyPI, npm, Docker, NuGet adapters
- GuardDog + Trivy + OSV scanners
- Local filesystem cache
- Block / quarantine / warn policies
- Community threat feed (read)
- Basic admin UI
- Docker Compose deployment
- SQLite database

### v1.1 — Hardening
- S3 / Azure Blob / GCS storage backends
- Maven, RubyGems, Go modules adapters
- Rescan scheduler
- Webhook / Slack / email alerts
- Helm chart
- Dynamic sandbox execution (gVisor)
- OIDC admin authentication
- PostgreSQL HA mode
- E2E test sandbox: containerized test clients (uv, npm, dotnet) running inside Docker so that E2E tests have zero dependency on host-installed toolchains and avoid local package-manager cache interference (~/.npm, ~/.nuget)

### v1.2 — Enterprise features
- SBOM generation per artifact
- License policy enforcement
- Dependency graph visualization
- SIEM integration (Splunk, Elastic)
- Community threat feed contributions portal

---

## 16. Contributing

Shieldoo Gate welcomes contributions under Apache 2.0.

```
CONTRIBUTING.md         contribution guidelines
SECURITY.md             responsible disclosure — security@shieldoo.io
docs/adr/               Architecture Decision Records (ADR)
docs/api/openapi.yaml   REST API OpenAPI spec
```

Threat intelligence contributions (new malicious package reports) are especially welcome — submit to the community feed repository at `github.com/shieldoo/threat-feed` as OSV-format JSON with evidence.

---

## 17. Prior Art & References

- [Harbor](https://goharbor.io/) — OCI registry with proxy cache and Trivy integration (Docker only)
- [Datadog GuardDog](https://github.com/DataDog/guarddog) — behavioral scanner for PyPI/npm (no proxy)
- [Datadog Supply-Chain Firewall](https://securitylabs.datadoghq.com/articles/introducing-supply-chain-firewall/) — local pip/npm wrapper (no proxy/cache)
- [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) — community threat database
- [Sonatype Nexus Firewall](https://www.sonatype.com/products/firewall) — commercial, closed source, inspiration
- [JFrog Curation](https://jfrog.com/xray/) — commercial, closed source, inspiration
- [devpi](https://devpi.net/) — PyPI proxy/mirror (no scanning)
- LiteLLM supply chain incident, March 2026 — primary motivation
- Trivy GitHub Actions compromise, March 2026 — primary motivation

---

*Shieldoo Gate — because your security scanner should not be your attack vector.*