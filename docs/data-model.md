# Data Model

> Database schema, Go model structs, and relationships.

## Overview

Shieldoo Gate uses **SQLite** (default, WAL mode, foreign keys enabled) or **PostgreSQL** (HA mode) with embedded SQL migrations. The schema is managed by `internal/config/db.go` using Go's `embed` package with a `schema_migrations` tracking table for run-once semantics. Migration files are organized by backend:

**SQLite** (`internal/config/migrations/sqlite/`):

- `001_init.sql` — Core tables (artifacts, scan_results, artifact_status, audit_log, threat_feed)
- `002_policy_overrides.sql` — Policy overrides table + lookup index
- `003_docker_registry.sql` — Docker repositories table + schema_migrations bootstrap
- `004_docker_tags.sql` — Docker tags table (tag-to-manifest-digest mapping)
- `005_audit_event_type_index.sql` — Add index on audit_log(event_type, ts)
- `006_rescan_scheduler.sql` — Rescan scheduler indexes + bootstrap rescan_due_at
- `007_audit_user_email.sql` — Add user_email column to audit_log
- `008_tag_digest_history.sql` — Tag digest history table for mutability detection
- `009_api_keys.sql` — API keys table for proxy authentication
- `010_api_keys_owner_index.sql` — Add index on api_keys(owner_email)
- `011_idx_artifacts_cached_at.sql` — Add index on artifacts(cached_at)
- `012_idx_artifacts_filters.sql` — Add indexes for artifact list filtering
- `013_unique_active_override.sql` — Partial unique index on active overrides (prevents duplicates)

- `014_triage_cache.sql` — AI triage decision cache table + audit log composite index
- `015_popular_packages.sql` — Popular packages table for typosquat scanner
- `016_version_diff_results.sql` — Version diff results table + composite artifact index
- `017_package_reputation.sql` — Package reputation scores table
- `018_projects.sql` — Projects table (lazy-created), seeds `default` project
- `019_audit_project_id.sql` — Adds `project_id` FK + `(project_id, ts)` index to `audit_log`
- `020_artifact_project_usage.sql` — Cross-table linking artifacts ↔ projects with usage counters
- `021_sbom_metadata.sql` — SBOM blob pointer + extracted licenses per artifact
- `022_project_license_policy.sql` — Per-project license policy (inherit/override/disabled)
- `023_global_license_policy.sql` — Singleton row holding the global license policy
- `024_version_diff_ai_columns.sql` — Extends `version_diff_results` with AI scanner columns, relaxes NOT NULL on legacy heuristic columns, deduplicates existing rows, adds the idempotency `UNIQUE INDEX uq_version_diff_pair`
- `025_version_diff_scanner_version.sql` — Adds `scanner_version` to `version_diff_results` plus `(scanner_version)` and `(verdict, diff_at)` indexes
- `026_project_policy_overrides.sql` — Adds `project_id` and `kind` (allow|deny) columns to `policy_overrides`; replaces the active-override unique index to include `COALESCE(project_id, 0)` and `kind`; adds `idx_policy_overrides_project_lookup`

**PostgreSQL** (`internal/config/migrations/postgres/`) — same migrations with PostgreSQL syntax.

In addition to SQL migrations, a separate **`data_migrations`** table tracks Go-level data backfills (see [`data_migrations`](#data_migrations) below). These run after schema migrations and use independent numbering — currently only `024_pypi_canonical_names`.

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
                      │   ┌──────────────────┐         ┌────────────────────────┐
                      ├──│   audit_log       │         │   sbom_metadata        │
                      │   │──────────────────│         │────────────────────────│
                      │   │ PK id (INTEGER)  │         │ PK artifact_id         │──▶ artifacts.id
                      │   │ ts               │         │ format                 │
                      │   │ event_type       │         │ blob_path              │
                      │   │ artifact_id      │ logical │ size_bytes             │
                      │   │ FK project_id    │──▶ projects.id  component_count  │
                      │   │ client_ip        │         │ licenses_json          │
                      │   │ user_agent       │         │ generated_at           │
                      │   │ reason           │         │ generator              │
                      │   │ metadata_json    │         └────────────────────────┘
                      │   │ user_email       │
                      │   └──────────────────┘
                      │
                      │   ┌──────────────────────────┐
                      └──│  artifact_project_usage   │
                          │──────────────────────────│
                          │ PK (artifact_id, project_id) │
                          │ FK artifact_id           │──▶ artifacts.id
                          │ FK project_id            │──▶ projects.id
                          │ first_used_at            │
                          │ last_used_at             │
                          │ use_count                │
                          └──────────────────────────┘

┌──────────────────┐     ┌──────────────────────┐    ┌──────────────────────┐
│    projects      │     │   policy_overrides    │    │  tag_digest_history  │
│──────────────────│     │──────────────────────│    │──────────────────────│
│ PK id (SERIAL)   │◀───│ FK project_id (NULL OK)│   │ PK id (INTEGER)      │
│ label (UNIQUE)   │     │ ecosystem            │    │ ecosystem            │
│ display_name     │     │ name                 │    │ name                 │
│ description      │     │ version              │    │ tag_or_version       │
│ created_at       │     │ scope                │    │ digest               │
│ created_via      │     │ kind (allow|deny)    │    │ first_seen_at        │
│ enabled          │     │ reason               │    └──────────────────────┘
└──────────────────┘     │ created_by           │
        ▲                │ created_at           │    ┌──────────────────┐
        │                │ expires_at           │    │   threat_feed    │
        │                │ revoked, revoked_at  │    │──────────────────│
        │                └──────────────────────┘    │ PK sha256 (TEXT) │
        │                                            │ ecosystem        │
        │  ┌──────────────────────────┐              │ package_name     │
        ├─│  project_license_policy   │              │ version          │
        │  │──────────────────────────│              │ reported_at      │
        │  │ PK id (SERIAL)           │              │ source_url       │
        │  │ FK project_id (UNIQUE)   │              │ iocs_json        │
        │  │ mode (inherit|override|  │              └──────────────────┘
        │  │       disabled)          │
        │  │ blocked_json/warned_json │              ┌──────────────────┐
        │  │ allowed_json             │              │    api_keys      │
        │  │ unknown_action           │              │──────────────────│
        │  │ updated_at, updated_by   │              │ PK id (BIGINT)   │
        │  └──────────────────────────┘              │ key_hash (UNIQUE)│
        │                                            │ name             │
        │  ┌──────────────────────────┐              │ owner_email      │
        │  │  global_license_policy   │              │ enabled          │
        │  │  (singleton, id = 1)     │              │ created_at       │
        │  │──────────────────────────│              │ last_used_at     │
        │  │ enabled                  │              │ expires_at       │
        │  │ blocked/warned/allowed   │              └──────────────────┘
        │  │ unknown_action           │
        │  │ on_sbom_error            │
        │  │ or_semantics             │
        │  │ updated_at, updated_by   │
        │  └──────────────────────────┘
        │

┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────────┐
│    triage_cache      │  │  popular_packages    │  │  version_diff_results    │
│──────────────────────│  │──────────────────────│  │──────────────────────────│
│ PK cache_key (TEXT)  │  │ PK (ecosystem, name) │  │ PK id (INTEGER)          │
│ ecosystem            │  │ rank                 │  │ artifact_id              │
│ name                 │  │ download_count       │  │ FK previous_artifact     │──▶ artifacts.id
│ version              │  │ last_updated         │  │ diff_at                  │
│ decision             │  └──────────────────────┘  │ files_added/removed/...  │
│ confidence           │                            │ size_ratio               │
│ explanation          │  ┌──────────────────────┐  │ verdict                  │
│ model_used           │  │ package_reputation   │  │ findings_json            │
│ created_at           │  │──────────────────────│  │ ai_verdict/confidence    │
│ expires_at           │  │ PK id (INTEGER)      │  │ ai_explanation           │
└──────────────────────┘  │ ecosystem            │  │ ai_model_used            │
                          │ name                 │  │ ai_prompt_version        │
┌──────────────────────┐  │ maintainers_json     │  │ ai_tokens_used           │
│  schema_migrations   │  │ risk_score           │  │ scanner_version          │
│  data_migrations     │  │ signals_json         │  │ previous_version         │
│  (run-once tables)   │  │ last_checked         │  └──────────────────────────┘
└──────────────────────┘  └──────────────────────┘
```

## Tables

### `artifacts`

Stores metadata about every artifact that has been downloaded and cached.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT PK | Composite key: `"{ecosystem}:{name}:{version}"` |
| `ecosystem` | TEXT NOT NULL | Package ecosystem (`pypi`, `npm`, `nuget`, `docker`, `maven`, `rubygems`, `go`) |
| `name` | TEXT NOT NULL | Package name |
| `version` | TEXT NOT NULL | Package version |
| `upstream_url` | TEXT NOT NULL | URL from which the artifact was downloaded |
| `sha256` | TEXT NOT NULL | SHA-256 hash of the artifact file |
| `size_bytes` | BIGINT NOT NULL | Artifact file size in bytes |
| `cached_at` | DATETIME NOT NULL | When the artifact was first cached |
| `last_accessed_at` | DATETIME NOT NULL | Last time a client requested this artifact |
| `storage_path` | TEXT NOT NULL | Relative path within the cache directory |

**Go struct:** `model.Artifact` (`internal/model/artifact.go`)

The `ID()` method computes the composite key: `fmt.Sprintf("%s:%s:%s", a.Ecosystem, a.Name, a.Version)`. When `Filename` is non-empty (e.g., PyPI wheels with distinct filenames per platform), the ID includes a fourth part: `fmt.Sprintf("%s:%s:%s:%s", a.Ecosystem, a.Name, a.Version, a.Filename)`.

**Indexes:**
- `idx_artifacts_ecosystem_name ON (ecosystem, name)`
- `idx_artifacts_name_version ON (name, version)`
- `idx_artifacts_cached_at ON (cached_at DESC)` — used for activity-style sorting
- `idx_artifacts_eco_name_cached ON (ecosystem, name, cached_at DESC)` — composite index for efficient previous-version lookup (used by version-diff scanner)
- `idx_artifacts_last_accessed ON (last_accessed_at)` — used by the rescan scheduler and LRU eviction

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

**Indexes:**
- `idx_artifact_status_status ON (status)` — for "list all quarantined" / "list all pending scan" admin queries
- `idx_artifact_status_rescan ON (status, rescan_due_at)` — used by the rescan scheduler to find PENDING_SCAN artifacts ready for re-evaluation

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
| `user_email` | TEXT DEFAULT '' | Email of the user who performed the action (v1.1, set when OIDC auth is active) |
| `project_id` | INTEGER FK | References `projects.id` — set when the event was driven by a per-project request (added by migration 019, may be NULL for system events) |

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
| `TAG_MUTATED` | Upstream tag/version digest changed (tag mutability detection) |
| `RESCAN_QUEUED` | Manual rescan triggered via API |

**Go struct:** `model.AuditEntry` (`internal/model/audit.go`)

**Indexes:**
- `idx_audit_log_ts ON (ts)`
- `idx_audit_log_event_type ON (event_type, ts)` — used by alert system per-channel filtering
- `idx_audit_log_artifact_event ON (artifact_id, event_type)` — for per-artifact audit lookups (added by migration 014)
- `idx_audit_project ON (project_id, ts)` — for per-project audit lookups (added by migration 019)

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
| `version` | TEXT NOT NULL DEFAULT '' | Package version (empty for package-scope overrides) |
| `scope` | TEXT NOT NULL | `version` (specific version) or `package` (all versions) |
| `reason` | TEXT NOT NULL DEFAULT '' | Reason for override (e.g., "False positive: safe package") |
| `created_by` | TEXT NOT NULL DEFAULT 'api' | User/API key that created the override |
| `created_at` | DATETIME NOT NULL | Creation timestamp |
| `expires_at` | DATETIME | Optional expiration (null = never expires) |
| `revoked` | BOOLEAN NOT NULL DEFAULT 0 | Soft-delete flag |
| `revoked_at` | DATETIME | When the override was revoked |
| `project_id` | INTEGER FK ON DELETE CASCADE | References `projects.id` — NULL means a global (cross-project) override; non-NULL is project-scoped (added by migration 026) |
| `kind` | TEXT NOT NULL DEFAULT 'allow' | `allow` (whitelist) or `deny` (blacklist) — enforced by `CHECK (kind IN ('allow', 'deny'))` (added by migration 026) |

**Go struct:** `model.PolicyOverride` (`internal/model/override.go`)

Key method: `Matches(ecosystem, name, version string) bool` — checks if the override applies to a given artifact, accounting for scope, revocation, and expiration. Note: the policy engine uses a direct SQL query for override matching (`engine.go:hasDBOverride()`), not this Go method.

**Indexes:**
- `idx_policy_overrides_lookup ON (ecosystem, name, version, revoked)` — fast override lookup
- `idx_policy_overrides_unique_active ON (ecosystem, name, version, scope, COALESCE(project_id, 0), kind) WHERE revoked = FALSE` — partial unique index preventing duplicate active overrides for the same (artifact, scope, project, kind) tuple. The `COALESCE(project_id, 0)` lets `NULL` (global override) coexist with project-scoped overrides on the same package. Replaces the pre-026 unique index, which did not include `project_id` or `kind`.
- `idx_policy_overrides_project_lookup ON (project_id, ecosystem, name, version, revoked)` — fast per-project override lookup (added by migration 026)

### `docker_repositories`

Tracks known Docker image repositories, both upstream (proxied) and internal (pushed).

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Repository ID |
| `registry` | TEXT NOT NULL DEFAULT '' | Registry hostname (empty for internal) |
| `name` | TEXT NOT NULL | Image name (e.g. `library/nginx`, `myteam/myapp`) |
| `is_internal` | BOOLEAN (SQLite: INTEGER) NOT NULL DEFAULT FALSE | TRUE / 1 for pushed (internal) images |
| `created_at` | DATETIME NOT NULL | Creation timestamp |
| `last_synced_at` | DATETIME | Last sync timestamp |
| `sync_enabled` | BOOLEAN (SQLite: INTEGER) NOT NULL DEFAULT TRUE | Whether scheduled sync is enabled |

**Go struct:** `docker.DockerRepository` (`internal/adapter/docker/repos.go`)

**Indexes:** `idx_docker_repos_registry_name ON (registry, name)` (UNIQUE)

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

**Indexes:**
- `idx_docker_tags_repo_tag ON (repo_id, tag)` (UNIQUE) — enforces the per-repo unique-tag constraint
- `idx_docker_tags_digest ON (manifest_digest)` — reverse lookup digest → tag(s)

### `tag_digest_history`

Tracks all observed digests for each ecosystem/name/version tuple. Used by tag mutability detection (`internal/adapter/mutability.go`) to identify upstream content changes.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Entry ID |
| `ecosystem` | TEXT NOT NULL | Package ecosystem |
| `name` | TEXT NOT NULL | Package or image name |
| `tag_or_version` | TEXT NOT NULL | Tag or version string |
| `digest` | TEXT NOT NULL | SHA-256 digest observed for this tag/version |
| `first_seen_at` | TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP | When this digest was first seen |

**Unique constraint:** `(ecosystem, name, tag_or_version, digest)`

**Indexes:** `idx_tag_digest_history_lookup ON (ecosystem, name, tag_or_version)`

### `api_keys`

API keys for proxy endpoint authentication. Keys are either per-user PATs (generated via admin API when OIDC is enabled) or a global shared token.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Key ID |
| `key_hash` | TEXT NOT NULL UNIQUE | SHA-256 hash of the API key (plain key is never stored) |
| `name` | TEXT NOT NULL | Human-readable key name |
| `owner_email` | TEXT NOT NULL DEFAULT '' | Email of the key owner (from OIDC) |
| `enabled` | INTEGER NOT NULL DEFAULT 1 | Whether the key is active |
| `created_at` | DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP | Creation timestamp |
| `last_used_at` | DATETIME | Last time the key was used for authentication |
| `expires_at` | DATETIME | Optional expiration (null = never expires) |

**Go struct:** `model.APIKey` (`internal/model/apikey.go`)

**Indexes:** `idx_api_keys_owner_email ON (owner_email)`

### `triage_cache`

Caches AI triage decisions for balanced policy mode. When the policy engine queries the AI triage service, the result is cached here to avoid redundant LLM calls for the same artifact.

| Column | Type | Description |
|---|---|---|
| `cache_key` | TEXT PK | Hash-based cache key (ecosystem + name + version + findings hash) |
| `ecosystem` | TEXT NOT NULL | Package ecosystem |
| `name` | TEXT NOT NULL | Package name |
| `version` | TEXT NOT NULL | Package version |
| `decision` | TEXT NOT NULL | Triage decision (`ALLOW`, `BLOCK`, `QUARANTINE`) |
| `confidence` | REAL NOT NULL | Decision confidence 0.0 to 1.0 |
| `explanation` | TEXT NOT NULL | LLM-generated explanation for the decision |
| `model_used` | TEXT NOT NULL | LLM model identifier used for the triage |
| `created_at` | TIMESTAMP NOT NULL | When the triage decision was made |
| `expires_at` | TIMESTAMP NOT NULL | TTL expiration (default 7 days) |

**Indexes:** `idx_triage_cache_expires ON (expires_at)` — for efficient expired entry cleanup

### `popular_packages`

Stores popular package names per ecosystem, used by the typosquat scanner for name-based attack detection. Seeded from embedded data on first run.

| Column | Type | Description |
|---|---|---|
| `ecosystem` | TEXT NOT NULL | Package ecosystem |
| `name` | TEXT NOT NULL | Popular package name |
| `rank` | INTEGER NOT NULL | Popularity rank within ecosystem |
| `download_count` | INTEGER | Download count (when available) |
| `last_updated` | DATETIME NOT NULL | When the entry was last refreshed |

**Primary Key:** `(ecosystem, name)`

**Indexes:** `idx_popular_packages_ecosystem ON (ecosystem, rank)` — for efficient top-N queries

### `version_diff_results`

Stores the results of cross-version comparison analysis performed by the version diff scanner. The schema was extended by migration `024_version_diff_ai_columns.sql` to support both the legacy heuristic scanner (rows with all-NULL AI columns) and the new AI-driven scanner (rows with non-NULL `ai_model_used` + `ai_prompt_version`).

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Result ID |
| `artifact_id` | TEXT NOT NULL | Artifact being analyzed |
| `previous_artifact` | TEXT NOT NULL FK | References `artifacts.id` — the previously cached version |
| `diff_at` | DATETIME NOT NULL | When the diff was performed |
| `verdict` | TEXT NOT NULL | Scanner verdict (`CLEAN` or `SUSPICIOUS`) |
| `findings_json` | TEXT NOT NULL | JSON array of `Finding` objects |
| `previous_version` | TEXT | Version string of the previous artifact (nullable; populated by AI scanner) |
| `files_added` | INTEGER | Number of new files in new version (nullable since migration 024) |
| `files_removed` | INTEGER | Number of removed files (nullable since migration 024) |
| `files_modified` | INTEGER | Number of modified files (nullable since migration 024) |
| `size_ratio` | REAL | Ratio of new version size to old version size (nullable since migration 024) |
| `max_entropy_delta` | REAL | Maximum Shannon entropy increase across files (nullable since migration 024) |
| `new_dependencies` | TEXT | JSON array of newly added dependencies |
| `sensitive_changes` | TEXT | JSON array of changed security-sensitive files |
| `ai_verdict` | TEXT | AI scanner verdict (nullable; NULL for legacy heuristic rows) |
| `ai_confidence` | REAL | AI confidence score 0.0–1.0 (nullable) |
| `ai_explanation` | TEXT | Human-readable AI explanation of the verdict (nullable) |
| `ai_model_used` | TEXT | AI model identifier (e.g. `gpt-5.4-mini`) (nullable) |
| `ai_prompt_version` | TEXT | SHA[:12] of the AI bridge system prompt at scan time (nullable) |
| `ai_tokens_used` | INTEGER | Total tokens consumed by the AI call (nullable) |
| `scanner_version` | TEXT | Version of the version-diff scanner that produced the row (nullable; legacy heuristic rows are NULL, v2.0+ rows write `'2.0.0'`) — added by migration 025 |

**Indexes:**
- `idx_version_diff_artifact ON (artifact_id)` — legacy artifact lookup index
- `uq_version_diff_pair UNIQUE ON (artifact_id, previous_artifact, ai_model_used, ai_prompt_version)` — idempotency cache key; rolling out a new model or prompt version invalidates all previous cache entries automatically
- `idx_version_diff_scanner_version ON (scanner_version)` — for filtering rows by scanner generation (added by migration 025)
- `idx_version_diff_verdict_diff_at ON (verdict, diff_at)` — used by `VersionDiffRetentionScheduler.runOnce` (`DELETE WHERE verdict='CLEAN' AND diff_at < ?`) (added by migration 025)

**NULL-distinct semantics of `uq_version_diff_pair`:** SQL `UNIQUE` treats `NULL` as distinct from every other value (including another `NULL`). This means legacy heuristic rows (with `ai_model_used = NULL` and `ai_prompt_version = NULL`) coexist in the same table alongside new AI-scanner rows that carry non-NULL values for both columns. A fresh AI scan with the same artifact pair but a different model or prompt version inserts a new row rather than colliding with an existing one.

**Indexes on `artifacts` table (added by migration 016, not 024):**
- `idx_artifacts_eco_name_cached ON artifacts(ecosystem, name, cached_at DESC)` — composite index for efficient previous-version lookup

### `package_reputation`

Caches upstream registry metadata and risk scores for the reputation scanner.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | Entry ID |
| `ecosystem` | TEXT NOT NULL | Package ecosystem |
| `name` | TEXT NOT NULL | Package name |
| `maintainers_json` | TEXT | JSON array of maintainer objects |
| `first_published` | DATETIME | When the package was first published |
| `latest_published` | DATETIME | When the latest version was published |
| `version_count` | INTEGER | Total number of published versions |
| `download_count` | INTEGER | Download count (when available) |
| `has_source_repo` | BOOLEAN NOT NULL DEFAULT 0 | Whether a source repository is linked |
| `source_repo_url` | TEXT | URL of the source repository |
| `description` | TEXT | Package description |
| `risk_score` | REAL NOT NULL DEFAULT 0.0 | Composite risk score (0.0–1.0) |
| `signals_json` | TEXT NOT NULL DEFAULT '{}' | JSON object of evaluated signal results |
| `last_checked` | DATETIME NOT NULL | When metadata was last fetched from upstream |

**Unique index:** `idx_package_reputation_eco_name ON (ecosystem, name)`

Entries older than `retention_days` (default 30) are cleaned up by a background goroutine at scanner startup.

### `projects`

Logical project / namespace used to scope artifact usage, license policy, and policy overrides. Projects are created lazily on first use (a request carrying a `?project=<label>` parameter) — the seed `default` project is inserted by migration 018 and is used when no `project=` is provided.

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | Project ID |
| `label` | TEXT NOT NULL UNIQUE | URL-safe slug (e.g. `default`, `team-platform`) — what clients pass in the `?project=` query parameter |
| `display_name` | TEXT | Human-readable name |
| `description` | TEXT | Optional description |
| `created_at` | TIMESTAMPTZ NOT NULL | Creation timestamp |
| `created_via` | TEXT NOT NULL DEFAULT 'lazy' | One of `lazy` (auto-created on request), `api` (explicit admin call), `seed` (the bootstrap row) |
| `enabled` | BOOLEAN NOT NULL DEFAULT TRUE | Disabled projects reject requests |

**Go struct:** `model.Project` (`internal/model/project.go`)

**Indexes:** `idx_projects_label ON (label)` (UNIQUE)

Referenced by `artifact_project_usage`, `audit_log`, `policy_overrides`, and `project_license_policy`.

### `artifact_project_usage`

Cross-table linking artifacts to the projects that have requested them. Updated on every successful artifact serve so the admin UI can show per-project package usage and last-used timestamps.

| Column | Type | Description |
|---|---|---|
| `artifact_id` | TEXT NOT NULL FK | References `artifacts.id` (ON DELETE CASCADE) |
| `project_id` | INTEGER NOT NULL FK | References `projects.id` (ON DELETE CASCADE) |
| `first_used_at` | TIMESTAMPTZ NOT NULL | First time this project requested this artifact |
| `last_used_at` | TIMESTAMPTZ NOT NULL | Most recent request timestamp |
| `use_count` | INTEGER NOT NULL DEFAULT 1 | Total request count |

**Primary Key:** `(artifact_id, project_id)`

**Indexes:** `idx_apu_project_last_used ON (project_id, last_used_at DESC)` — for "recent activity in project X" queries

### `sbom_metadata`

Per-artifact SBOM blob pointer plus extracted licenses. The actual SBOM document (CycloneDX/SPDX JSON) lives on disk at `blob_path`; this row stores the index. Used by the license policy engine to evaluate the global/per-project license policies without re-parsing the SBOM on every request.

| Column | Type | Description |
|---|---|---|
| `artifact_id` | TEXT PK FK | References `artifacts.id` (ON DELETE CASCADE) |
| `format` | TEXT NOT NULL | SBOM format (e.g. `cyclonedx-1.5`, `spdx-2.3`) |
| `blob_path` | TEXT NOT NULL | Relative path to the SBOM blob in the cache directory |
| `size_bytes` | BIGINT NOT NULL | Size of the SBOM document |
| `component_count` | INTEGER NOT NULL DEFAULT 0 | Number of components extracted from the SBOM |
| `licenses_json` | TEXT NOT NULL DEFAULT '[]' | JSON array of unique SPDX license IDs found across components |
| `generated_at` | TIMESTAMPTZ NOT NULL | When the SBOM was generated |
| `generator` | TEXT NOT NULL | SBOM generator name (e.g. `trivy`, `syft`) |

**Indexes:** `idx_sbom_generated_at ON (generated_at)` — for retention/cleanup queries

The licenses surfaced in the admin UI's Artifacts list (`ArtifactWithStatus.licenses`) come from this table — the API joins `artifacts ⨝ artifact_status ⨝ sbom_metadata` and decodes `licenses_json`.

### `project_license_policy`

Per-project override of the global license policy. One row per project (UNIQUE on `project_id`).

| Column | Type | Description |
|---|---|---|
| `id` | SERIAL PK | Row ID |
| `project_id` | INTEGER NOT NULL UNIQUE FK | References `projects.id` (ON DELETE CASCADE) |
| `mode` | TEXT NOT NULL DEFAULT 'inherit' | One of `inherit` (use global), `override` (use this row), `disabled` (allow everything for this project) |
| `blocked_json` | TEXT | JSON array of SPDX IDs to block (only used when `mode = 'override'`) |
| `warned_json` | TEXT | JSON array of SPDX IDs to warn on |
| `allowed_json` | TEXT | JSON array of SPDX IDs to explicitly allow |
| `unknown_action` | TEXT | What to do with unknown SPDX IDs: `allow`, `warn`, `block`, or empty (inherit from global) |
| `updated_at` | TIMESTAMPTZ NOT NULL | Last update timestamp |
| `updated_by` | TEXT | User who last updated the policy |

### `global_license_policy`

Singleton row (CHECK constraint `id = 1`) holding the global license policy used by all projects with `mode = 'inherit'`. The application uses an UPSERT on `id = 1` to create or update this single row.

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Always 1 (enforced by `CHECK (id = 1)`) |
| `enabled` | BOOLEAN NOT NULL DEFAULT TRUE | Master switch — `FALSE` disables license enforcement globally |
| `blocked_json` | TEXT | JSON array of SPDX IDs to block |
| `warned_json` | TEXT | JSON array of SPDX IDs to warn on |
| `allowed_json` | TEXT | JSON array of SPDX IDs to explicitly allow |
| `unknown_action` | TEXT | Action for SPDX IDs not in any list: `allow`, `warn`, or `block` |
| `on_sbom_error` | TEXT | Action when SBOM generation fails: `allow`, `warn`, or `block` |
| `or_semantics` | TEXT | How to evaluate `OR` license expressions: `any_allowed` (permissive — pass if any operand allowed) or `all_allowed` (strict — pass only if all operands allowed) |
| `updated_at` | TIMESTAMPTZ NOT NULL | Last update timestamp |
| `updated_by` | TEXT | User who last updated the policy |

If the row is missing (fresh install before first admin save), the API falls back to the policy embedded in `config.yaml` (`source: 'config'`).

### `schema_migrations`

Tracks which SQL migrations have been applied. Prevents re-running migrations.

| Column | Type | Description |
|---|---|---|
| `version` | INTEGER PK | Migration number (e.g., 1, 2, 3...) |
| `applied_at` | DATETIME NOT NULL | When the migration was applied |

### `data_migrations`

Tracks Go-level data backfills run after SQL migrations (see `internal/config/data_migrations.go`). Used when the rewrite logic is more natural in Go than in cross-dialect SQL — for example reusing existing canonicalization helpers. Numbering is independent of `schema_migrations`.

| Column | Type | Description |
|---|---|---|
| `name` | TEXT PK | Migration name (e.g. `024_pypi_canonical_names`) |
| `applied_at` | TIMESTAMP NOT NULL | When the migration was applied |

## Artifact ID Convention

Throughout the system, artifacts are identified by the composite string `"{ecosystem}:{name}:{version}"`:

- `pypi:requests:2.32.3`
- `npm:chalk:5.3.0`
- `nuget:Newtonsoft.Json:13.0.3`
- `docker:docker_io_library_postgres:18.2-alpine` — see Docker note below
- `maven:org.apache.commons:commons-lang3:3.14.0` (4-part: `ecosystem:groupId:artifactId:version`)
- `rubygems:rake:13.2.1`
- `go:golang.org/x/text:v0.14.0`

**Docker:** the `name` segment is **not** the original `registry/path` — `internal/adapter/docker.MakeSafeName(registry, imagePath)` slug-encodes registry + path into a filesystem-safe identifier (slashes/dots become underscores). Examples:

- `docker:docker_io_library_postgres:18.2-alpine` (a tag pull)
- `docker:docker_io_library_postgres:sha256:1b13c640...` (a manifest-digest pull — version is the full `sha256:...` digest)
- `docker:docker_io_pgvector_pgvector:sha256:b48c110f...`

The same image can therefore appear as multiple rows: one per tag pull and one per manifest digest accessed by clients. The Docker UI groups these by repository name (see `docker_repositories`), and the resolved tag→digest mapping lives in `docker_tags`.

This ID is used as the primary key in the `artifacts` table and as the `artifact_id` foreign key in related tables. It is computed by `model.Artifact.ID()` and URL-encoded/decoded when used in API paths.
