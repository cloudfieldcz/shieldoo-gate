# Protocol Adapters

> How Shieldoo Gate proxies package manager protocols, routes requests, and triggers scanning.

## Overview

Each adapter implements the native protocol of a package manager so that **zero client-side changes** are needed beyond pointing the package manager at Shieldoo Gate's URL. Adapters are registered as `http.Handler` implementations, each running on its own port.

All adapters share a common base (`internal/adapter/base.go`) that provides:

- **Input validation** — Package names and versions validated against `^[a-zA-Z0-9._\-]+$`
- **Audit logging** — `WriteAuditLog()` inserts entries into the `audit_log` table
- **Artifact status lookups** — `GetArtifactStatus()` checks the current status before serving
- **Scan result persistence** — `InsertScanResults()` stores scanner output
- **Transactional artifact insertion** — `InsertArtifact()` atomically inserts artifact + status rows
- **Error responses** — `WriteJSONError()` returns structured JSON errors for blocked/quarantined requests

## Common Scan-on-Download Flow

All adapters (except Docker, see below) follow this pattern when a client requests an artifact download:

```
1. Parse package name + version from URL
2. Validate input (reject invalid characters)
3. Compute artifact ID: "{ecosystem}:{name}:{version}"
4. Check artifact_status in DB:
   │
   ├── QUARANTINED → return 403 with JSON error
   ├── CLEAN (cached) → serve from local cache
   └── Not found → continue to step 5
   │
5. Download artifact from upstream registry to temp file
6. Compute SHA-256 hash
7. Call scanEngine.ScanAll() — all scanners run in parallel
8. Call policyEngine.Evaluate() with scan results:
   │
   ├── ALLOW → cache artifact, set status CLEAN, serve to client, log SERVED
   ├── BLOCK → set status QUARANTINED, return 403, log BLOCKED
   └── QUARANTINE → cache artifact, set status QUARANTINED, return 403, log QUARANTINED
   │
9. Persist scan results to scan_results table
```

### Blocked Response Format

When an artifact is blocked or quarantined, the adapter returns HTTP 403 with:

```json
{
  "error": "artifact_quarantined",
  "artifact": "pypi:litellm:1.82.7",
  "reason": "verdict MALICIOUS meets block threshold",
  "details_url": "http://localhost:8080/api/v1/artifacts/pypi%3Alitellm%3A1.82.7"
}
```

## PyPI Adapter

| | |
|---|---|
| **Package** | `internal/adapter/pypi/` |
| **Protocol** | [PEP 503](https://peps.python.org/pep-0503/) Simple Repository API |
| **Default port** | 5000 |
| **Default upstream** | `https://pypi.org` |
| **Compatible clients** | `pip`, `uv`, `poetry`, `pdm` |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/simple/` | Package index — lists all available packages |
| `GET` | `/simple/{package}/` | Package file list — lists available versions and download links |
| `GET` | `/packages/{path...}` | **Download artifact** — triggers scan if not cached |

### How It Works

1. **Index and file list requests** (`/simple/`, `/simple/{package}/`) are proxied directly to PyPI. The response HTML is rewritten to point download URLs at the local proxy instead of `files.pythonhosted.org`.

2. **Download requests** (`/packages/...`) trigger the scan-on-download flow. The adapter extracts the package name and version from the URL path, downloads the `.tar.gz` or `.whl` file from upstream, scans it, and either serves or blocks it.

3. Scanned file types: `.tar.gz`, `.whl`, `.zip` — the built-in PTH Inspector specifically looks for `.pth` files inside wheel archives (the LiteLLM attack vector).

### Client Configuration

```bash
# pip
pip config set global.index-url http://shieldoo-gate:5000/simple/

# uv
# uv.toml
[pip]
index-url = "http://shieldoo-gate:5000/simple/"
```

## npm Adapter

| | |
|---|---|
| **Package** | `internal/adapter/npm/` |
| **Protocol** | npm Registry API |
| **Default port** | 4873 |
| **Default upstream** | `https://registry.npmjs.org` |
| **Compatible clients** | `npm`, `yarn`, `pnpm` |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/{package}` | Package metadata — full package document with all versions |
| `GET` | `/{package}/{version}` | Version metadata — specific version info |
| `GET` | `/{package}/-/{tarball}` | **Download tarball** — triggers scan if not cached |

### How It Works

1. **Metadata requests** are proxied to the upstream npm registry. The response JSON is rewritten to point tarball URLs at the local proxy.

2. **Tarball downloads** trigger scanning. The adapter extracts the package name (including scoped packages like `@scope/name`) and version from the tarball filename, downloads the `.tgz` file, scans it, and either serves or blocks it.

3. Scoped packages (`@org/package`) are supported — the `@` scope is preserved in routing.

### Client Configuration

```bash
npm config set registry http://shieldoo-gate:4873/
```

## NuGet Adapter

| | |
|---|---|
| **Package** | `internal/adapter/nuget/` |
| **Protocol** | [NuGet V3 API](https://learn.microsoft.com/en-us/nuget/api/overview) |
| **Default port** | 5001 |
| **Default upstream** | `https://api.nuget.org` |
| **Compatible clients** | `dotnet`, `nuget.exe`, Visual Studio, MSBuild |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/v3/index.json` | Service index — lists available API resources |
| `GET` | `/v3/registration/{id}/index.json` | Package metadata — registration page |
| `GET` | `/v3-flatcontainer/{id}/{version}/{filename}` | **Download .nupkg** — triggers scan if not cached |

### How It Works

1. **Service index** (`/v3/index.json`) is rewritten to point resource URLs at the local proxy instead of `api.nuget.org`.

2. **Registration requests** are proxied and rewritten similarly.

3. **Package downloads** (`/v3-flatcontainer/...`) trigger scanning. The adapter extracts the package ID, version, and filename, downloads the `.nupkg` file, scans it, and either serves or blocks it.

### Client Configuration

```bash
dotnet nuget add source http://shieldoo-gate:5001/v3/index.json --name shieldoo-gate
```

## Docker Adapter

| | |
|---|---|
| **Package** | `internal/adapter/docker/` |
| **Protocol** | [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) v1.1 |
| **Default port** | 5002 |
| **Default upstream** | `https://registry-1.docker.io` (configurable, multi-registry) |
| **Compatible clients** | `docker`, `podman`, `containerd` |

### Multi-Upstream Routing

The Docker adapter supports pulling from **multiple upstream registries**. The first path segment after `/v2/` determines the target registry:

- If the first segment contains a **dot** (`.`) or **colon** (`:`), it is treated as a registry hostname and matched against the `allowed_registries` allowlist.
- If no dot/colon is found, the request goes to the **default registry** (Docker Hub).
- **Bare image names** (e.g. `nginx`) automatically get `library/` prepended per Docker Hub convention.
- Requests to registries **not in the allowlist** are rejected with HTTP 403.

**Examples:**
| Client Request | Resolved Upstream |
|---|---|
| `docker pull shieldoo:5002/nginx` | Docker Hub → `library/nginx` |
| `docker pull shieldoo:5002/myuser/myapp` | Docker Hub → `myuser/myapp` |
| `docker pull shieldoo:5002/ghcr.io/org/image` | `ghcr.io` → `org/image` |
| `docker pull shieldoo:5002/evil.io/pkg` | **403 Forbidden** (not in allowlist) |

**SECURITY:** Client `Authorization` headers are **never forwarded** to upstream registries. Gate authenticates to each upstream independently using per-registry credentials from config (`auth.token_env` environment variable reference).

### Push Support (Internal Images)

When `push.enabled: true` is set in config, the Docker adapter supports `docker push` for **internal namespaces** (images whose first path segment does not contain a dot or colon). Push to upstream registry namespaces (e.g. `ghcr.io/...`) is always rejected.

**Push flow:**
1. Client initiates blob upload (`POST /v2/{name}/blobs/uploads/`) and receives a session UUID.
2. Client uploads blob data with digest (`PUT /v2/{name}/blobs/uploads/{uuid}?digest=sha256:...`). The adapter verifies the digest matches the uploaded content.
3. Client pushes the manifest (`PUT /v2/{name}/manifests/{ref}`). The adapter **scans the manifest before returning success** (Security Invariant #2).
4. If the scan passes policy evaluation, the manifest is stored, the tag is recorded in `docker_tags`, and `201 Created` is returned.
5. If the scan fails, the push is rejected with `403 Forbidden`.

**Internal namespace detection:**
- Images with a slash where the first segment has no dot/colon are internal (e.g. `myteam/myapp`).
- Bare names without a slash (e.g. `nginx`) are NOT pushable (they resolve to Docker Hub).
- Registry-prefixed names (e.g. `ghcr.io/user/app`) are NOT pushable.

**Blob storage:** Pushed blobs are stored on the local filesystem at `{blob_path}/blobs/{algo}/{prefix}/{hex}` with two-level directory sharding. Path traversal in digest values is rejected.

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/v2/` | Version check — responds locally with `Docker-Distribution-API-Version: registry/2.0` |
| `GET` | `/v2/{name}/manifests/{reference}` | Pull manifest (by tag or digest) — triggers scan pipeline |
| `GET` | `/v2/{name}/blobs/{digest}` | Pull layer blob — proxied to resolved upstream |
| `POST` | `/v2/{name}/blobs/uploads/` | Initiate blob upload (push) — returns 202 with Location header |
| `PUT` | `/v2/{name}/blobs/uploads/{uuid}` | Complete monolithic blob upload with digest verification |
| `PUT` | `/v2/{name}/manifests/{reference}` | Push manifest — scans before accepting |
| `HEAD` | `/v2/{name}/blobs/{digest}` | Check blob existence (internal or upstream proxy) |

### How It Works

The Docker adapter implements a **scan-on-pull pipeline** for manifest requests. When a client pulls an image:

1. **Registry resolution** — the `RegistryResolver` determines the upstream from the image name and validates against the allowlist.
2. **Repository tracking** — the `docker_repositories` table is updated via `EnsureRepository` (atomic INSERT OR IGNORE + SELECT).
3. **Manifest request** triggers the full scan pipeline: the adapter fetches the manifest from upstream (with per-registry auth), verifies the manifest digest against upstream's `Docker-Content-Digest` header, then pulls the complete image to a temporary OCI tarball using `go-containerregistry` (crane).
4. **Trivy scans** the tarball (CVEs, misconfigurations, secrets in layers).
5. **Policy evaluation** determines whether to serve, block, or quarantine the image.
6. **Clean images** have their manifest cached and served to the client. Subsequent pulls for the same image:tag are served from cache.
7. **Blob requests** (`/v2/{name}/blobs/{digest}`) are passed through directly to the resolved upstream — scanning happens at the manifest/image level, not per-layer.

The `X-Shieldoo-Scanned: true` response header is set on all scanned manifest responses so clients and CI systems can verify inspection occurred.

### Artifact ID Format

Artifact IDs use safe names: `docker:{safe_name}:{ref}` where `safe_name` replaces dots and slashes with underscores. For example, `ghcr.io/org/image:latest` becomes `docker:ghcr_io_org_image:latest`.

### Scheduled Sync (Background Re-scan)

When `sync.enabled: true` is set in the Docker upstream config, a `SyncService` runs as a background goroutine that periodically re-pulls manifests from upstream registries and re-scans cached images. This catches newly discovered vulnerabilities in previously clean images.

**How it works:**

1. On each sync interval, the service queries all repositories where `sync_enabled=true` and `is_internal=false`, ordered by `last_synced_at ASC` (least recently synced first).
2. For each repository, it iterates all tags and fetches the upstream manifest.
3. **Digest comparison:** If the upstream manifest digest differs from the stored `docker_tags.manifest_digest`, the image has changed upstream and is re-scanned.
4. **Rescan interval:** If the digest is unchanged but `rescan_interval` has elapsed since the last scan, the image is re-scanned anyway (catches new CVE database entries).
5. **Policy evaluation** runs on re-scanned images. If a previously clean image now triggers quarantine, it is quarantined.
6. Concurrency is controlled by a semaphore (`max_concurrent`).

**Error handling:**

| Error | Behavior |
|---|---|
| Upstream unreachable | Log warning, skip repository, continue to next |
| HTTP 404 | Disable sync for the repository (`sync_enabled=false`) |
| HTTP 429 | Log warning, respect Retry-After header, skip |
| Scan failure | Fail open (log error, do not quarantine) |

**Configuration:**

```yaml
upstreams:
  docker:
    sync:
      enabled: true
      interval: "6h"          # How often to run the sync cycle
      rescan_interval: "24h"  # Re-scan unchanged images after this duration
      max_concurrent: 3       # Max concurrent repository syncs
```

**SECURITY:** The sync service uses per-registry credentials from config, never client Authorization headers. Scan failures fail open per Security Invariant #2.

### Client Configuration

```json
// /etc/docker/daemon.json
{ "registry-mirrors": ["http://shieldoo-gate:5002"] }
```

## Port Summary

| Ecosystem | Default Port | Docker Compose Host Port |
|---|---|---|
| PyPI | 5000 | 5010 (avoids macOS AirPlay conflict on 5000) |
| npm | 4873 | 4873 |
| NuGet | 5001 | 5001 |
| Docker | 5002 | 5002 |
| Admin API | 8080 | 8080 |
