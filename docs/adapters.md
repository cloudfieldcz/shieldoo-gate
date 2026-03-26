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
| **Default upstream** | `https://registry-1.docker.io` |
| **Compatible clients** | `docker`, `podman`, `containerd` |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/v2/` | Version check |
| `GET` | `/v2/{name}/manifests/{reference}` | Pull manifest (by tag or digest) |
| `GET` | `/v2/{name}/blobs/{digest}` | Pull layer blob |
| `GET` | `/v2/*` | Other OCI distribution spec routes |

### How It Works

The Docker adapter operates differently from the other adapters. It currently acts as a **transparent proxy** — forwarding pull traffic to the upstream registry without inline scanning.

Docker image scanning is handled **out-of-band** by Trivy, which can scan images by reference. The adapter proxies manifests and blobs directly, and scanning happens asynchronously when configured.

This approach is taken because Docker images consist of multiple layers (blobs) that must be assembled before meaningful scanning can occur, unlike single-file artifacts (`.whl`, `.tgz`, `.nupkg`).

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
