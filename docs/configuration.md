# Configuration

> Complete reference for `config.yaml` and environment variable overrides.

## Overview

Shieldoo Gate is configured via a YAML file (default: `config.yaml`, override with `-config` flag). All settings can also be overridden via environment variables with the `SGW_` prefix.

Configuration is loaded by `internal/config/config.go` using [Viper](https://github.com/spf13/viper).

## Full Configuration Reference

```yaml
# config.yaml — Shieldoo Gate v1.0

# ─── Server ────────────────────────────────────────────────────────
server:
  host: "0.0.0.0"             # Bind address for all listeners

# ─── Ports ─────────────────────────────────────────────────────────
# Each ecosystem adapter and the admin API run on separate ports
ports:
  pypi: 5000                   # PyPI PEP 503 proxy
  npm: 4873                    # npm registry proxy
  nuget: 5001                  # NuGet V3 proxy
  docker: 5002                 # Docker/OCI distribution proxy
  admin: 8080                  # Admin REST API + React UI

# ─── Upstreams ─────────────────────────────────────────────────────
# Upstream registries to proxy. Requests for packages are forwarded here.
upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
  nuget: "https://api.nuget.org"
  docker:
    default_registry: "https://registry-1.docker.io"  # Default upstream for Docker Hub images
    allowed_registries:              # Non-default registries that clients can pull from
      - host: "ghcr.io"             # Registry hostname (matched against first path segment)
        url: "https://ghcr.io"      # Upstream URL to proxy to
      - host: "quay.io"
        url: "https://quay.io"
        auth:                        # Optional per-registry credentials
          type: "bearer"             # "bearer" or "basic"
          token_env: "QUAY_TOKEN"    # Env var name containing the token (NEVER stored in config)
    sync:
      enabled: true                  # Enable scheduled background sync (Phase 3)
      interval: "6h"                 # How often to sync repositories
      rescan_interval: "24h"         # How often to rescan synced images
      max_concurrent: 3              # Max concurrent sync workers
    push:
      enabled: false                 # Enable push support (Phase 2)

# ─── Cache ─────────────────────────────────────────────────────────
cache:
  backend: "local"             # "local" (default), "s3", "azure_blob", or "gcs"
  local:
    path: "/var/cache/shieldoo-gate"   # Directory for cached artifacts
    max_size_gb: 50                     # Maximum cache size (informational)
  s3:
    bucket: ""                         # S3 bucket name (required when backend is "s3")
    region: "us-east-1"                # AWS region (required unless endpoint is set)
    endpoint: ""                       # Custom endpoint for MinIO / S3-compatible
    prefix: ""                         # Optional key prefix
    force_path_style: false            # Set true for MinIO
    access_key_env: ""                 # Env var name for access key (optional)
    secret_key_env: ""                 # Env var name for secret key (optional)
  azure_blob:
    account_name: ""                   # Azure storage account name
    container_name: ""                 # Blob container name (required when backend is "azure_blob")
    connection_string_env: ""          # Env var name for connection string (optional)
    prefix: ""                         # Optional key prefix for all blobs
  gcs:
    bucket: ""                         # GCS bucket name (required when backend is "gcs")
    credentials_file: ""               # Path to service account JSON (optional)
    prefix: ""                         # Optional key prefix for all objects
  ttl:                         # Per-ecosystem cache TTL
    pypi: "168h"               # 7 days
    npm: "168h"                # 7 days
    nuget: "168h"              # 7 days
    docker: "720h"             # 30 days

# ─── Database ──────────────────────────────────────────────────────
database:
  backend: "sqlite"            # "sqlite" (default) or "postgres"
  sqlite:
    path: "/var/lib/shieldoo-gate/gate.db"   # SQLite database file path
  postgres:
    # DSN should be provided via env var SGW_DATABASE_POSTGRES_DSN
    # to avoid committing credentials to version control.
    dsn: ""                    # Required when backend is "postgres"
    max_open_conns: 25         # Connection pool: max open connections
    max_idle_conns: 5          # Connection pool: max idle connections
    conn_max_lifetime: "5m"    # Connection pool: max connection lifetime

# ─── Scanners ──────────────────────────────────────────────────────
scanners:
  parallel: true               # Run scanners in parallel (recommended)
  timeout: "60s"               # Per-scan timeout for all scanners

  guarddog:
    enabled: true              # Enable GuardDog behavioral scanner
    bridge_socket: "/tmp/shieldoo-bridge.sock"   # Unix socket path to Python bridge

  trivy:
    enabled: true              # Enable Trivy vulnerability scanner
    binary: "trivy"            # Path to trivy binary
    cache_dir: "/var/cache/trivy"   # Trivy's own vulnerability DB cache

  osv:
    enabled: true              # Enable OSV.dev vulnerability lookup
    api_url: "https://api.osv.dev"  # OSV API endpoint

# ─── Policy ────────────────────────────────────────────────────────
policy:
  block_if_verdict: "MALICIOUS"      # Block artifacts with this verdict
  quarantine_if_verdict: "SUSPICIOUS" # Quarantine artifacts with this verdict
  minimum_confidence: 0.7             # Ignore scanner results below this confidence
  allowlist:                          # Static allowlist (bypasses all scan checks)
    - "pypi:litellm:==1.82.6"        # Format: "ecosystem:name[:==version]"

# ─── Threat Feed ───────────────────────────────────────────────────
threat_feed:
  enabled: true                       # Enable community threat feed
  url: "https://feed.shieldoo.io/malicious-packages.json"  # Feed URL
  refresh_interval: "1h"             # How often to refresh the feed

# ─── Rescan Scheduler (v1.1) ──────────────────────────────────────
# Periodically re-scans cached artifacts to detect newly discovered threats.
# Processes PENDING_SCAN artifacts first (from manual rescan API), then
# CLEAN/SUSPICIOUS artifacts ordered by most recently accessed.
rescan:
  enabled: true                       # Enable the rescan scheduler
  interval: "6h"                      # How often the scheduler runs a batch
  batch_size: 100                     # Max artifacts per cycle
  max_concurrent: 5                   # Max parallel scans per cycle

# ─── Logging ───────────────────────────────────────────────────────
log:
  level: "info"                # debug | info | warn | error
  format: "json"               # json | text (text uses human-readable console output)

# ─── Alerts (v1.1) ────────────────────────────────────────────────
# Real-time notifications for security events.
# Each channel is independent — enable any combination.
# Secrets are NEVER stored in config; use *_env fields to reference
# environment variables that hold the actual secret value.
alerts:
  webhook:
    enabled: false
    url: "https://siem.example.com/api/events"  # Must be HTTPS (see allow_insecure)
    secret_env: "ALERT_WEBHOOK_SECRET"           # Env var for HMAC-SHA256 signing key
    allow_insecure: false                        # Set true to allow plain HTTP (dev only)
    on: []                                       # Event filter; empty = ALL events
    # Valid event types: SERVED, BLOCKED, QUARANTINED, RELEASED, SCANNED,
    #   OVERRIDE_CREATED, OVERRIDE_REVOKED, TAG_MUTATED, RESCAN_QUEUED

  slack:
    enabled: false
    webhook_env: "ALERT_SLACK_WEBHOOK"           # Env var for Slack incoming webhook URL
    on: ["BLOCKED", "QUARANTINED", "TAG_MUTATED"]  # Only high-priority events

  email:
    enabled: false
    host: "smtp.example.com"
    port: 587                                    # 587 (STARTTLS) or 465 (implicit TLS)
    from: "shieldoo@example.com"
    to:                                          # One or more recipient addresses
      - "security-team@example.com"
    username_env: "ALERT_EMAIL_USER"             # Env var for SMTP username
    password_env: "ALERT_EMAIL_PASS"             # Env var for SMTP password
    use_tls: false                               # Force implicit TLS (port 465)
    tls_skip_verify: false                       # Skip certificate validation (dev only)
    batch_interval: "30s"                        # Accumulate events before sending digest
    on: ["BLOCKED", "QUARANTINED"]               # Event filter
```

## Environment Variable Overrides

Every config key can be overridden via environment variables using the `SGW_` prefix. Nested keys use `_` as separator:

| Config Key | Environment Variable | Example |
|---|---|---|
| `server.host` | `SGW_SERVER_HOST` | `SGW_SERVER_HOST=127.0.0.1` |
| `ports.pypi` | `SGW_PORTS_PYPI` | `SGW_PORTS_PYPI=5050` |
| `upstreams.pypi` | `SGW_UPSTREAMS_PYPI` | `SGW_UPSTREAMS_PYPI=https://pypi.internal.com` |
| `cache.backend` | `SGW_CACHE_BACKEND` | `SGW_CACHE_BACKEND=s3` |
| `cache.local.path` | `SGW_CACHE_LOCAL_PATH` | `SGW_CACHE_LOCAL_PATH=/data/cache` |
| `cache.s3.bucket` | `SGW_CACHE_S3_BUCKET` | `SGW_CACHE_S3_BUCKET=shieldoo-cache` |
| `cache.s3.region` | `SGW_CACHE_S3_REGION` | `SGW_CACHE_S3_REGION=us-east-1` |
| `cache.s3.endpoint` | `SGW_CACHE_S3_ENDPOINT` | `SGW_CACHE_S3_ENDPOINT=http://minio:9000` |
| `cache.s3.prefix` | `SGW_CACHE_S3_PREFIX` | `SGW_CACHE_S3_PREFIX=artifacts` |
| `cache.s3.force_path_style` | `SGW_CACHE_S3_FORCE_PATH_STYLE` | `SGW_CACHE_S3_FORCE_PATH_STYLE=true` |
| `cache.azure_blob.account_name` | `SGW_CACHE_AZURE_BLOB_ACCOUNT_NAME` | `SGW_CACHE_AZURE_BLOB_ACCOUNT_NAME=myaccount` |
| `cache.azure_blob.container_name` | `SGW_CACHE_AZURE_BLOB_CONTAINER_NAME` | `SGW_CACHE_AZURE_BLOB_CONTAINER_NAME=shieldoo-cache` |
| `cache.azure_blob.connection_string_env` | `SGW_CACHE_AZURE_BLOB_CONNECTION_STRING_ENV` | `SGW_CACHE_AZURE_BLOB_CONNECTION_STRING_ENV=AZURE_CONN_STR` |
| `cache.azure_blob.prefix` | `SGW_CACHE_AZURE_BLOB_PREFIX` | `SGW_CACHE_AZURE_BLOB_PREFIX=artifacts` |
| `cache.gcs.bucket` | `SGW_CACHE_GCS_BUCKET` | `SGW_CACHE_GCS_BUCKET=shieldoo-cache` |
| `cache.gcs.credentials_file` | `SGW_CACHE_GCS_CREDENTIALS_FILE` | `SGW_CACHE_GCS_CREDENTIALS_FILE=/etc/gcs-key.json` |
| `cache.gcs.prefix` | `SGW_CACHE_GCS_PREFIX` | `SGW_CACHE_GCS_PREFIX=artifacts` |
| `database.backend` | `SGW_DATABASE_BACKEND` | `SGW_DATABASE_BACKEND=postgres` |
| `database.sqlite.path` | `SGW_DATABASE_SQLITE_PATH` | `SGW_DATABASE_SQLITE_PATH=/data/gate.db` |
| `database.postgres.dsn` | `SGW_DATABASE_POSTGRES_DSN` | `SGW_DATABASE_POSTGRES_DSN=postgres://user:pass@host/db` |
| `database.postgres.max_open_conns` | `SGW_DATABASE_POSTGRES_MAX_OPEN_CONNS` | `SGW_DATABASE_POSTGRES_MAX_OPEN_CONNS=50` |
| `scanners.timeout` | `SGW_SCANNERS_TIMEOUT` | `SGW_SCANNERS_TIMEOUT=120s` |
| `scanners.guarddog.enabled` | `SGW_SCANNERS_GUARDDOG_ENABLED` | `SGW_SCANNERS_GUARDDOG_ENABLED=false` |
| `scanners.guarddog.bridge_socket` | `SGW_SCANNERS_GUARDDOG_BRIDGE_SOCKET` | `SGW_SCANNERS_GUARDDOG_BRIDGE_SOCKET=/tmp/bridge.sock` |
| `scanners.trivy.enabled` | `SGW_SCANNERS_TRIVY_ENABLED` | `SGW_SCANNERS_TRIVY_ENABLED=false` |
| `scanners.osv.enabled` | `SGW_SCANNERS_OSV_ENABLED` | `SGW_SCANNERS_OSV_ENABLED=false` |
| `policy.block_if_verdict` | `SGW_POLICY_BLOCK_IF_VERDICT` | `SGW_POLICY_BLOCK_IF_VERDICT=MALICIOUS` |
| `policy.minimum_confidence` | `SGW_POLICY_MINIMUM_CONFIDENCE` | `SGW_POLICY_MINIMUM_CONFIDENCE=0.8` |
| `threat_feed.enabled` | `SGW_THREAT_FEED_ENABLED` | `SGW_THREAT_FEED_ENABLED=false` |
| `rescan.enabled` | `SGW_RESCAN_ENABLED` | `SGW_RESCAN_ENABLED=true` |
| `rescan.interval` | `SGW_RESCAN_INTERVAL` | `SGW_RESCAN_INTERVAL=12h` |
| `rescan.batch_size` | `SGW_RESCAN_BATCH_SIZE` | `SGW_RESCAN_BATCH_SIZE=50` |
| `rescan.max_concurrent` | `SGW_RESCAN_MAX_CONCURRENT` | `SGW_RESCAN_MAX_CONCURRENT=3` |
| `log.level` | `SGW_LOG_LEVEL` | `SGW_LOG_LEVEL=debug` |
| `log.format` | `SGW_LOG_FORMAT` | `SGW_LOG_FORMAT=text` |
| `alerts.webhook.enabled` | `SGW_ALERTS_WEBHOOK_ENABLED` | `SGW_ALERTS_WEBHOOK_ENABLED=true` |
| `alerts.webhook.url` | `SGW_ALERTS_WEBHOOK_URL` | `SGW_ALERTS_WEBHOOK_URL=https://siem.example.com/api/events` |
| `alerts.slack.enabled` | `SGW_ALERTS_SLACK_ENABLED` | `SGW_ALERTS_SLACK_ENABLED=true` |
| `alerts.email.enabled` | `SGW_ALERTS_EMAIL_ENABLED` | `SGW_ALERTS_EMAIL_ENABLED=true` |
| `alerts.email.host` | `SGW_ALERTS_EMAIL_HOST` | `SGW_ALERTS_EMAIL_HOST=smtp.example.com` |

Environment variables take precedence over the YAML config file.

## Go Config Structs

The configuration is deserialized into Go structs defined in `internal/config/config.go`:

| Struct | Config Section | Key Fields |
|---|---|---|
| `Config` | root | Top-level container for all sections |
| `ServerConfig` | `server` | `Host` |
| `PortsConfig` | `ports` | `PyPI`, `NPM`, `NuGet`, `Docker`, `Admin` |
| `UpstreamsConfig` | `upstreams` | `PyPI`, `NPM`, `NuGet`, `Docker` (struct) |
| `DockerUpstreamConfig` | `upstreams.docker` | `DefaultRegistry`, `AllowedRegistries`, `Sync`, `Push` |
| `DockerRegistryEntry` | `upstreams.docker.allowed_registries[]` | `Host`, `URL`, `Auth` |
| `DockerRegistryAuth` | `...allowed_registries[].auth` | `Type`, `TokenEnv` |
| `DockerSyncConfig` | `upstreams.docker.sync` | `Enabled`, `Interval`, `RescanInterval`, `MaxConcurrent` |
| `DockerPushConfig` | `upstreams.docker.push` | `Enabled` |
| `CacheConfig` | `cache` | `Backend`, `Local`, `S3`, `AzureBlob`, `GCS`, `TTL` |
| `LocalCacheConfig` | `cache.local` | `Path`, `MaxSizeGB` |
| `S3CacheConfig` | `cache.s3` | `Bucket`, `Region`, `Endpoint`, `Prefix`, `ForcePathStyle`, `AccessKeyEnv`, `SecretKeyEnv` |
| `AzureBlobConfig` | `cache.azure_blob` | `AccountName`, `ContainerName`, `ConnectionStrEnv`, `Prefix` |
| `GCSCacheConfig` | `cache.gcs` | `Bucket`, `CredentialsFile`, `Prefix` |
| `TTLConfig` | `cache.ttl` | `PyPI`, `NPM`, `NuGet`, `Docker` |
| `DatabaseConfig` | `database` | `Backend`, `SQLite`, `Postgres` |
| `SQLiteConfig` | `database.sqlite` | `Path` |
| `PostgresConfig` | `database.postgres` | `DSN`, `MaxOpenConns`, `MaxIdleConns`, `ConnMaxLifetime` |
| `ScannersConfig` | `scanners` | `Parallel`, `Timeout`, `GuardDog`, `Trivy`, `OSV` |
| `GuardDogConfig` | `scanners.guarddog` | `Enabled`, `BridgeSocket` |
| `TrivyConfig` | `scanners.trivy` | `Enabled`, `Binary`, `CacheDir` |
| `OSVConfig` | `scanners.osv` | `Enabled`, `APIURL` |
| `PolicyConfig` | `policy` | `BlockIfVerdict`, `QuarantineIfVerdict`, `MinimumConfidence`, `Allowlist` |
| `ThreatFeedConfig` | `threat_feed` | `Enabled`, `URL`, `RefreshInterval` |
| `RescanConfig` | `rescan` | `Enabled`, `Interval`, `BatchSize`, `MaxConcurrent` |
| `LogConfig` | `log` | `Level`, `Format` |
| `AlertsConfig` | `alerts` | `Webhook`, `Slack`, `Email` |
| `WebhookAlertConfig` | `alerts.webhook` | `Enabled`, `URL`, `SecretEnv`, `AllowInsecure`, `On` |
| `SlackAlertConfig` | `alerts.slack` | `Enabled`, `WebhookEnv`, `On` |
| `EmailAlertConfig` | `alerts.email` | `Enabled`, `Host`, `Port`, `From`, `To`, `UsernameEnv`, `PasswordEnv`, `UseTLS`, `TLSSkipVerify`, `BatchInterval`, `On` |

## Validation

`Config.Validate()` checks required fields:

- When `cache.backend` is `local` (or empty), `cache.local.path` must be non-empty
- When `cache.backend` is `s3`, `cache.s3.bucket` must be non-empty, and `cache.s3.region` must be set unless a custom `cache.s3.endpoint` is provided
- When `cache.backend` is `azure_blob`, `cache.azure_blob.container_name` must be non-empty, and either `account_name` or `connection_string_env` must be set
- When `cache.backend` is `gcs`, `cache.gcs.bucket` must be non-empty
- Unknown `cache.backend` values are rejected
- When `database.backend` is `sqlite` (or empty), `database.sqlite.path` must be non-empty
- When `database.backend` is `postgres`, `database.postgres.dsn` must be non-empty
- Unknown `database.backend` values are rejected
- When `rescan.enabled` is `true`: `rescan.interval` must be a valid Go duration, `rescan.batch_size` >= 0, `rescan.max_concurrent` >= 0

## Rescan Scheduler (v1.1)

The rescan scheduler periodically re-scans cached artifacts to detect newly discovered threats (zero-day window closure). It is implemented in `internal/scheduler/rescan.go`.

**Priority ordering:** `PENDING_SCAN` artifacts (from manual `POST /api/v1/artifacts/{id}/rescan`) are processed first. Then `CLEAN` and `SUSPICIOUS` artifacts with `rescan_due_at <= now`, ordered by most recently accessed (`last_accessed_at DESC`).

**Fail-open semantics:** Scanner errors preserve the current artifact status and never escalate to `QUARANTINED`. Cache misses skip the artifact and clear `rescan_due_at`.

**Concurrency control:** Uses a semaphore to limit parallel scans to `max_concurrent`.

**Alerting integration:** When an artifact is reclassified as `QUARANTINED` during rescan, `WriteAuditLog` fires the alert hook automatically.

## S3 Cache Backend

When `cache.backend` is set to `"s3"`, artifacts are stored in an Amazon S3 bucket (or S3-compatible service like MinIO). This enables shared cache across multiple Shieldoo Gate instances for HA deployments.

### Object Key Layout

Objects are stored using the format `{prefix}/{ecosystem}/{name}/{version}/{sha256}`:

```
s3://my-bucket/
├── pypi/requests/2.31.0/a3cf1bc...
├── npm/lodash/4.17.21/def456...
├── docker/library__nginx/latest/ghi789...
└── nuget/Newtonsoft.Json/13.0.3/jkl012...
```

### Authentication

The S3 backend supports two authentication modes:

1. **Standard AWS credential chain** (default): Uses `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` environment variables, shared credentials file (`~/.aws/credentials`), or IAM instance/pod roles.

2. **Explicit env var references**: Set `access_key_env` and `secret_key_env` in config to reference environment variable names holding the credentials. Secrets are **never** stored in the config file.

### MinIO / S3-Compatible Services

```yaml
cache:
  backend: "s3"
  s3:
    bucket: "shieldoo-cache"
    endpoint: "http://minio:9000"
    force_path_style: true
    access_key_env: "MINIO_ACCESS_KEY"
    secret_key_env: "MINIO_SECRET_KEY"
```

### Integrity Verification

After every download from S3, the SHA256 hash of the downloaded content is verified against the hash stored in the object key. If the hash does not match, the file is rejected and a CRITICAL error is logged. This protects against compromised buckets, storage corruption, or man-in-the-middle attacks.

### Temp File Cleanup

The S3 `Get()` method downloads objects to temporary files. These temp files are automatically cleaned up 5 minutes after creation via a background goroutine.

### Stats Caching

`Stats()` results are cached in memory and refreshed at most every 5 minutes to avoid expensive S3 list operations.

## Azure Blob Storage Cache Backend

When `cache.backend` is set to `"azure_blob"`, artifacts are stored in an Azure Blob Storage container. This enables shared cache across multiple Shieldoo Gate instances deployed on Azure.

### Object Key Layout

Blobs use the same format as S3: `{prefix}/{ecosystem}/{name}/{version}/{sha256}`.

### Authentication

The Azure Blob backend supports two authentication modes:

1. **Connection string** (via env var): Set `connection_string_env` to the name of an environment variable holding the Azure Storage connection string. Secrets are **never** stored in the config file.

2. **DefaultAzureCredential** (managed identity): When no connection string is available, the SDK falls back to `DefaultAzureCredential`, which supports managed identity, Azure CLI, environment variables (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), and other standard mechanisms.

### Example Configuration

```yaml
cache:
  backend: "azure_blob"
  azure_blob:
    account_name: "myshieldoostorage"
    container_name: "shieldoo-cache"
    connection_string_env: "AZURE_STORAGE_CONNECTION_STRING"
    prefix: "artifacts"
```

### Integrity Verification

After every download from Azure Blob Storage, the SHA256 hash of the downloaded content is verified against the hash stored in the object key. If the hash does not match, the file is rejected and a CRITICAL error is logged.

### Temp File Cleanup

The Azure Blob `Get()` method downloads blobs to temporary files. These temp files are automatically cleaned up 5 minutes after creation via a background goroutine.

### Stats Caching

`Stats()` results are cached in memory and refreshed at most every 5 minutes to avoid expensive list operations.

## Google Cloud Storage (GCS) Cache Backend

When `cache.backend` is set to `"gcs"`, artifacts are stored in a Google Cloud Storage bucket. This enables shared cache across multiple Shieldoo Gate instances deployed on GCP.

### Object Key Layout

Objects use the same format as S3: `{prefix}/{ecosystem}/{name}/{version}/{sha256}`.

### Authentication

The GCS backend supports two authentication modes:

1. **Explicit credentials file**: Set `credentials_file` to the path of a service account JSON key file.

2. **Application Default Credentials** (default): When `credentials_file` is not set, the SDK uses `GOOGLE_APPLICATION_CREDENTIALS` environment variable, GCE metadata service, or workload identity.

### Example Configuration

```yaml
cache:
  backend: "gcs"
  gcs:
    bucket: "shieldoo-cache"
    credentials_file: "/etc/shieldoo/gcs-key.json"
    prefix: "artifacts"
```

### Integrity Verification

After every download from GCS, the SHA256 hash of the downloaded content is verified against the hash stored in the object key. If the hash does not match, the file is rejected and a CRITICAL error is logged.

### Temp File Cleanup

The GCS `Get()` method downloads objects to temporary files. These temp files are automatically cleaned up 5 minutes after creation via a background goroutine.

### Stats Caching

`Stats()` results are cached in memory and refreshed at most every 5 minutes to avoid expensive list operations.

## Local Cache Storage Layout

Artifacts are stored under the configured cache path, organized by ecosystem:

```
/var/cache/shieldoo-gate/
├── pypi/
│   └── requests/
│       └── 2.32.3/
│           └── requests-2.32.3-py3-none-any.whl
├── npm/
│   └── chalk/
│       └── 5.3.0/
│           └── chalk-5.3.0.tgz
├── nuget/
│   └── Newtonsoft.Json/
│       └── 13.0.3/
│           └── newtonsoft.json.13.0.3.nupkg
└── docker/
    └── library/
        └── python/
            └── sha256_abc123...
```

## Allowlist Format

Allowlist entries in `policy.allowlist` use this format:

```
{ecosystem}:{name}[:=={version}]
```

Examples:
- `pypi:litellm:==1.82.6` — Allow only version 1.82.6
- `npm:lodash` — Allow all versions of lodash
- `nuget:Newtonsoft.Json:==13.0.3` — Allow only version 13.0.3
