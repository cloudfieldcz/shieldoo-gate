# Data Model

> Database schema, Go model structs, and relationships.

## Overview

Shieldoo Gate uses **SQLite** (WAL mode, foreign keys enabled) with embedded SQL migrations. The schema is managed by `internal/config/db.go` using Go's `embed` package with a `schema_migrations` tracking table for run-once semantics. Migration files:

- `internal/config/migrations/001_init.sql` — Core tables (artifacts, scan_results, artifact_status, audit_log, threat_feed)
- `internal/config/migrations/002_policy_overrides.sql` — Policy overrides table
- `internal/config/migrations/003_docker_registry.sql` — Docker repositories table + schema_migrations bootstrap
- `internal/config/migrations/004_docker_tags.sql` — Docker tags table (tag-to-manifest-digest mapping for pushed images)

SQLite PRAGMAs applied at startup:
```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
```

## Entity Relationship Diagram

```
┌─────────────────┐       ┌──────────────────┐
│    artifacts     │       │   scan_results   │
│─────────────────│       │──────────────────│
│ PK id (TEXT)     │◀──┐   │ PK id (INTEGER)  │
│ ecosystem        │   │   │ FK artifact_id   │──▶ artifacts.id
│ name             │   │   │ scanned_at       │
│ version          │   │   │ scanner_name     │
│ upstream_url     │   │   │ scanner_version  │
│ sha256           │   │   │ verdict          │
│ size_bytes       │   │   │ confidence       │
│ cached_at        │   │   │ findings_json    │
│ last_accessed_at │   │   │ duration_ms      │
│ storage_path     │   │   └──────────────────┘
└─────────────────┘   │
                      │   ┌──────────────────┐
                      ├──│ artifact_status   │
                      │   │──────────────────│
                      │   │ PK artifact_id   │──▶ artifacts.id
                      │   │ status           │
                      │   │ quarantine_reason │
                      │   │ quarantined_at   │
                      │   │ released_at      │
                      │   │ rescan_due_at    │
                      │   │ FK last_scan_id  │──▶ scan_results.id
                      │   └──────────────────┘
                      │
                      │   ┌──────────────────┐
                      └──│   audit_log       │
                          │──────────────────│
                          │ PK id (INTEGER)  │
                          │ ts               │
                          │ event_type       │
                          │ artifact_id      │  (logical FK, not enforced)
                          │ client_ip        │
                          │ user_agent       │
                          │ reason           │
                          │ metadata_json    │
                          └──────────────────┘

┌──────────────────┐     ┌──────────────────┐
│   threat_feed    │     │ policy_overrides  │
│──────────────────│     │──────────────────│
│ PK sha256 (TEXT) │     │ PK id (INTEGER)  │
│ ecosystem        │     │ ecosystem        │
│ package_name     │     │ name             │
│ version          │     │ version          │
│ reported_at      │     │ scope            │
│ source_url       │     │ reason           │
│ iocs_json        │     │ created_by       │
└──────────────────┘     │ created_at       │
                         │ expires_at       │
                         │ revoked          │
                         │ revoked_at       │
                         └──────────────────┘
```

## Tables

### `artifacts`

Stores metadata about every artifact that has been downloaded and cached.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PK | Composite key: `"{ecosystem}:{name}:{version}"` |
| `ecosystem` | TEXT NOT NULL | Package ecosystem (`pypi`, `npm`, `nuget`, `docker`) |
| `name` | TEXT NOT NULL | Package name |
| `version` | TEXT NOT NULL | Package version |
| `upstream_url` | TEXT NOT NULL | URL from which the artifact was downloaded |
| `sha256` | TEXT NOT NULL | SHA-256 hash of the artifact file |
| `size_bytes` | INTEGER NOT NULL | Artifact file size in bytes |
| `cached_at` | DATETIME NOT NULL | When the artifact was first cached |
| `last_accessed_at` | DATETIME NOT NULL | Last time a client requested this artifact |
| `storage_path` | TEXT NOT NULL | Relative path within the cache directory |

**Go struct:** `model.Artifact` (`internal/model/artifact.go`)

The `ID()` method computes the composite key: `fmt.Sprintf("%s:%s:%s", a.Ecosystem, a.Name, a.Version)`.

**Indexes:** `idx_artifacts_ecosystem_name ON (ecosystem, name)`

### `scan_results`

One row per artifact per scanner run. Multiple scanners produce multiple rows for the same artifact.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Unique scan result ID |
| `artifact_id` | TEXT NOT NULL FK | References `artifacts.id` |
| `scanned_at` | DATETIME NOT NULL | Scan start timestamp |
| `scanner_name` | TEXT NOT NULL | Scanner identifier (e.g., `builtin-hash-verifier`, `trivy`, `guarddog`) |
| `scanner_version` | TEXT NOT NULL | Scanner version at time of scan |
| `verdict` | TEXT NOT NULL | `CLEAN`, `SUSPICIOUS`, or `MALICIOUS` |
| `confidence` | REAL NOT NULL | Confidence score 0.0 to 1.0 |
| `findings_json` | TEXT NOT NULL | JSON array of `Finding` objects |
| `duration_ms` | INTEGER NOT NULL | Scan duration in milliseconds |

**Go struct:** `model.ScanResult` (`internal/model/scan.go`)

**Indexes:** `idx_scan_results_artifact ON (artifact_id)`

#### Finding JSON Structure

Each element in `findings_json` follows this structure:

```json
{
  "severity": "HIGH",
  "category": "obfuscation",
  "description": "Base64-encoded exec() call detected in setup.py",
  "location": "setup.py:42",
  "iocs": ["models.litellm.cloud"]
}
```

Severity levels: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### `artifact_status`

Denormalized current status for each artifact. Enables fast lookups without joining scan_results. One row per artifact (1:1 with `artifacts`).

| Column | Type | Description |
|---|---|---|
| `artifact_id` | TEXT PK FK | References `artifacts.id` |
| `status` | TEXT NOT NULL | `CLEAN`, `SUSPICIOUS`, `QUARANTINED`, or `PENDING_SCAN` |
| `quarantine_reason` | TEXT | Human-readable reason for quarantine |
| `quarantined_at` | DATETIME | When the artifact was quarantined |
| `released_at` | DATETIME | When the artifact was released from quarantine |
| `rescan_due_at` | DATETIME | When a rescan should be triggered (used by manual rescan) |
| `last_scan_id` | INTEGER FK | References `scan_results.id` — the most recent scan |

**Go struct:** `model.ArtifactStatus` (`internal/model/artifact.go`)

Key method: `IsServable() bool` — returns `true` if status is not `QUARANTINED`. This is the final gate that prevents serving quarantined artifacts.

**Status transitions:**

```
                    ┌─── rescan/release ───┐
                    ▼                      │
PENDING_SCAN ──▶ CLEAN ──▶ QUARANTINED ───┘
                    │            ▲
                    ▼            │
               SUSPICIOUS ──────┘
```

- `PENDING_SCAN` → set on manual rescan request
- `CLEAN` → default after scan returns no actionable findings
- `SUSPICIOUS` → scan found concerning patterns below block threshold
- `QUARANTINED` → scan returned MALICIOUS or manual quarantine by admin

### `audit_log`

**Append-only** log of all significant events. No UPDATE or DELETE operations are ever performed on this table.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Unique entry ID |
| `ts` | DATETIME NOT NULL | Event timestamp |
| `event_type` | TEXT NOT NULL | Event type (see below) |
| `artifact_id` | TEXT | Related artifact ID (may be null for system events) |
| `client_ip` | TEXT | Client IP address for request events |
| `user_agent` | TEXT | Client user-agent string |
| `reason` | TEXT | Human-readable reason or description |
| `metadata_json` | TEXT | Additional JSON metadata |

**Event types:**

| Event | When |
|---|---|
| `SERVED` | Artifact successfully served to a client |
| `BLOCKED` | Artifact blocked due to MALICIOUS verdict |
| `QUARANTINED` | Artifact placed in quarantine |
| `RELEASED` | Artifact released from quarantine by admin |
| `SCANNED` | Scan completed for an artifact |
| `OVERRIDE_CREATED` | Policy override created via API |
| `OVERRIDE_REVOKED` | Policy override revoked via API |
| `RESCAN_QUEUED` | Manual rescan triggered via API |

**Go struct:** `model.AuditEntry` (`internal/model/audit.go`)

**Indexes:** `idx_audit_log_ts ON (ts)`

### `threat_feed`

Stores entries from the community threat feed. Used by the built-in threat feed checker scanner for fast-path SHA256 lookups.

| Column | Type | Description |
|---|---|---|
| `sha256` | TEXT PK | SHA-256 hash of the known-malicious artifact |
| `ecosystem` | TEXT NOT NULL | Package ecosystem |
| `package_name` | TEXT NOT NULL | Package name |
| `version` | TEXT | Specific version (may be null) |
| `reported_at` | DATETIME NOT NULL | When the threat was first reported |
| `source_url` | TEXT | Link to the threat report |
| `iocs_json` | TEXT | JSON array of indicators of compromise |

**Go struct:** `model.ThreatFeedEntry` (`internal/model/threat.go`)

**Indexes:** `idx_threat_feed_ecosystem ON (ecosystem, package_name)`

Entries are upserted by the `threatfeed.Client` during periodic refresh using `INSERT OR REPLACE`.

### `policy_overrides`

User-created exceptions that allow artifacts through the policy engine despite scanner findings. Supports both version-specific and package-wide overrides with optional expiration.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Override ID |
| `ecosystem` | TEXT NOT NULL | Package ecosystem |
| `name` | TEXT NOT NULL | Package name |
| `version` | TEXT | Package version (null for package-scope overrides) |
| `scope` | TEXT NOT NULL | `version` (specific version) or `package` (all versions) |
| `reason` | TEXT | Reason for override (e.g., "False positive: safe package") |
| `created_by` | TEXT NOT NULL | User/API key that created the override |
| `created_at` | DATETIME NOT NULL | Creation timestamp |
| `expires_at` | DATETIME | Optional expiration (null = never expires) |
| `revoked` | BOOLEAN NOT NULL DEFAULT 0 | Soft-delete flag |
| `revoked_at` | DATETIME | When the override was revoked |

**Go struct:** `model.PolicyOverride` (`internal/model/override.go`)

Key method: `Matches(ecosystem, name, version string) bool` — checks if the override applies to a given artifact, accounting for scope, revocation, and expiration.

### `docker_repositories`

Tracks known Docker image repositories, both upstream (proxied) and internal (pushed).

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Repository ID |
| `registry` | TEXT NOT NULL DEFAULT '' | Registry hostname (empty for internal) |
| `name` | TEXT NOT NULL | Image name (e.g. `library/nginx`, `myteam/myapp`) |
| `is_internal` | INTEGER NOT NULL DEFAULT 0 | 1 for pushed (internal) images |
| `created_at` | DATETIME NOT NULL | Creation timestamp |
| `last_synced_at` | DATETIME | Last sync timestamp |
| `sync_enabled` | INTEGER NOT NULL DEFAULT 1 | Whether scheduled sync is enabled |

**Go struct:** `docker.DockerRepository` (`internal/adapter/docker/repos.go`)

### `docker_tags`

Maps tag names to manifest digests for Docker repositories. Used primarily for pushed images.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Tag ID |
| `repo_id` | INTEGER NOT NULL FK | References `docker_repositories.id` |
| `tag` | TEXT NOT NULL | Tag name (e.g. `v1.0`, `latest`) |
| `manifest_digest` | TEXT NOT NULL | SHA256 digest of the manifest |
| `artifact_id` | TEXT FK | References `artifacts.id` (nullable) |
| `created_at` | DATETIME NOT NULL | Creation timestamp |
| `updated_at` | DATETIME NOT NULL | Last update timestamp |

**Go struct:** `docker.DockerTag` (`internal/adapter/docker/tags.go`)

**Unique constraint:** `(repo_id, tag)` — each tag name is unique per repository. Pushing the same tag again updates the digest (like `docker push myapp:latest`).

## Artifact ID Convention

Throughout the system, artifacts are identified by the composite string `"{ecosystem}:{name}:{version}"`:

- `pypi:requests:2.32.3`
- `npm:chalk:5.3.0`
- `nuget:Newtonsoft.Json:13.0.3`
- `docker:library/python:3.12-slim`

This ID is used as the primary key in the `artifacts` table and as the `artifact_id` foreign key in related tables. It is computed by `model.Artifact.ID()` and URL-encoded/decoded when used in API paths.
