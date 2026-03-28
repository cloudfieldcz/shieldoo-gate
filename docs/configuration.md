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
  backend: "local"             # Only "local" is implemented in v1.0
  local:
    path: "/var/cache/shieldoo-gate"   # Directory for cached artifacts
    max_size_gb: 50                     # Maximum cache size (informational)
  ttl:                         # Per-ecosystem cache TTL
    pypi: "168h"               # 7 days
    npm: "168h"                # 7 days
    nuget: "168h"              # 7 days
    docker: "720h"             # 30 days

# ─── Database ──────────────────────────────────────────────────────
database:
  backend: "sqlite"            # Only "sqlite" is implemented in v1.0
  sqlite:
    path: "/var/lib/shieldoo-gate/gate.db"   # SQLite database file path

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
| `cache.backend` | `SGW_CACHE_BACKEND` | `SGW_CACHE_BACKEND=local` |
| `cache.local.path` | `SGW_CACHE_LOCAL_PATH` | `SGW_CACHE_LOCAL_PATH=/data/cache` |
| `database.sqlite.path` | `SGW_DATABASE_SQLITE_PATH` | `SGW_DATABASE_SQLITE_PATH=/data/gate.db` |
| `scanners.timeout` | `SGW_SCANNERS_TIMEOUT` | `SGW_SCANNERS_TIMEOUT=120s` |
| `scanners.guarddog.enabled` | `SGW_SCANNERS_GUARDDOG_ENABLED` | `SGW_SCANNERS_GUARDDOG_ENABLED=false` |
| `scanners.guarddog.bridge_socket` | `SGW_SCANNERS_GUARDDOG_BRIDGE_SOCKET` | `SGW_SCANNERS_GUARDDOG_BRIDGE_SOCKET=/tmp/bridge.sock` |
| `scanners.trivy.enabled` | `SGW_SCANNERS_TRIVY_ENABLED` | `SGW_SCANNERS_TRIVY_ENABLED=false` |
| `scanners.osv.enabled` | `SGW_SCANNERS_OSV_ENABLED` | `SGW_SCANNERS_OSV_ENABLED=false` |
| `policy.block_if_verdict` | `SGW_POLICY_BLOCK_IF_VERDICT` | `SGW_POLICY_BLOCK_IF_VERDICT=MALICIOUS` |
| `policy.minimum_confidence` | `SGW_POLICY_MINIMUM_CONFIDENCE` | `SGW_POLICY_MINIMUM_CONFIDENCE=0.8` |
| `threat_feed.enabled` | `SGW_THREAT_FEED_ENABLED` | `SGW_THREAT_FEED_ENABLED=false` |
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
| `CacheConfig` | `cache` | `Backend`, `Local`, `TTL` |
| `LocalCacheConfig` | `cache.local` | `Path`, `MaxSizeGB` |
| `TTLConfig` | `cache.ttl` | `PyPI`, `NPM`, `NuGet`, `Docker` |
| `DatabaseConfig` | `database` | `Backend`, `SQLite` |
| `SQLiteConfig` | `database.sqlite` | `Path` |
| `ScannersConfig` | `scanners` | `Parallel`, `Timeout`, `GuardDog`, `Trivy`, `OSV` |
| `GuardDogConfig` | `scanners.guarddog` | `Enabled`, `BridgeSocket` |
| `TrivyConfig` | `scanners.trivy` | `Enabled`, `Binary`, `CacheDir` |
| `OSVConfig` | `scanners.osv` | `Enabled`, `APIURL` |
| `PolicyConfig` | `policy` | `BlockIfVerdict`, `QuarantineIfVerdict`, `MinimumConfidence`, `Allowlist` |
| `ThreatFeedConfig` | `threat_feed` | `Enabled`, `URL`, `RefreshInterval` |
| `LogConfig` | `log` | `Level`, `Format` |
| `AlertsConfig` | `alerts` | `Webhook`, `Slack`, `Email` |
| `WebhookAlertConfig` | `alerts.webhook` | `Enabled`, `URL`, `SecretEnv`, `AllowInsecure`, `On` |
| `SlackAlertConfig` | `alerts.slack` | `Enabled`, `WebhookEnv`, `On` |
| `EmailAlertConfig` | `alerts.email` | `Enabled`, `Host`, `Port`, `From`, `To`, `UsernameEnv`, `PasswordEnv`, `UseTLS`, `TLSSkipVerify`, `BatchInterval`, `On` |

## Validation

`Config.Validate()` checks required fields:

- When `cache.backend` is `local`, `cache.local.path` must be non-empty
- When `database.backend` is `sqlite`, `database.sqlite.path` must be non-empty

## Cache Storage Layout

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
