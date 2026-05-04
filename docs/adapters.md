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
  "error": "blocked",
  "artifact": "pypi:litellm:1.82.7",
  "reason": "verdict MALICIOUS meets block threshold"
}
```

The `error` field is `"blocked"` when the policy action is BLOCK, or `"quarantined"` when the action is QUARANTINE.

### Upstream Metadata Proxy Size Limit

The npm, PyPI, and NuGet adapters proxy package metadata (packuments, simple index, registration pages) from the upstream registry, rewriting absolute URLs so artifact downloads route back through the proxy. These metadata responses are streamed directly to the client and **not cached on disk** — only artifact content (tarballs, wheels, .nupkg) is stored in the cache.

To protect against DoS from a malicious or misbehaving upstream, metadata responses are capped at **200 MB**. If an upstream response exceeds the cap, the proxy returns `502 Bad Gateway` with `upstream metadata exceeds size limit` rather than truncating the body — silent truncation would corrupt JSON/XML and produce confusing client-side parse errors. Large public packuments (e.g. `vite`, `react`, `webpack`) routinely exceed 10 MB; 200 MB leaves substantial headroom.

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

### Package Name Normalization

PyPI distributes the same package under two name forms — the [PEP 503](https://peps.python.org/pep-0503/#normalized-names) canonical form on the simple index (`strawberry-graphql`, hyphens, lowercase) and the [PEP 427](https://peps.python.org/pep-0427/#file-name-convention) wheel-filename form (`strawberry_graphql`, with underscores so the filename can be split on `-`).

Shieldoo Gate stores every PyPI artifact under its **PEP 503 canonical name**. This is the single source of truth used by:

- the artifact ID (`pypi:strawberry-graphql:0.263.0:strawberry_graphql-0.263.0-py3-none-any.whl` — note the canonical name in segment 2 and the wheel filename verbatim in segment 4),
- the admin UI Artifacts table search,
- the static `policy:allowlist` in `config.yaml`,
- entries created in the `policy_overrides` table by the admin API.

The allowlist parser and the override-creation API canonicalize their input, so an admin may write `pypi:strawberry-graphql:==0.263.0` or `pypi:strawberry_graphql:==0.263.0` interchangeably; both round-trip to the canonical form. See [ADR-003](adr/ADR-003-pypi-canonical-package-names.md) for the full rationale.

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

**HTTP/2 is required for Docker Hub.** All upstream traffic from the gate goes through `adapter.NewProxyHTTPClient`, which sets `Transport.ForceAttemptHTTP2 = true`. Without that flag, Go's `http.Transport` silently disables HTTP/2 whenever a custom `DialContext` is supplied (per Go's `http.Transport` documentation), and Cloudflare's WAF on `auth.docker.io` rejects Go's HTTP/1.1 client fingerprint with HTTP 403 — breaking every Docker Hub pull. The token-exchange error message also surfaces the upstream response body so the next time a WAF / rate-limit rule kicks in, the rejection reason is visible from logs alone.

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
| `PATCH` | `/v2/{name}/blobs/uploads/{uuid}` | Chunked blob upload data (OCI Distribution Spec) |
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

## Maven Adapter

| | |
|---|---|
| **Package** | `internal/adapter/maven/` |
| **Protocol** | Maven Repository HTTP Layout |
| **Default port** | 8085 |
| **Default upstream** | `https://repo1.maven.org/maven2` |
| **Compatible clients** | `mvn`, `gradle`, `sbt`, `leiningen` |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/*` | Catch-all — path is parsed to determine action |

### Path Layout

Maven uses a path-based layout where the group ID is encoded as directory segments:

```
/{groupPath}/{artifactId}/{version}/{artifactId}-{version}[-{classifier}].{ext}
```

Example: `org.apache.commons:commons-lang3:3.14.0` maps to:
```
/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar
```

### How It Works

1. **Scannable files** (`.jar`, `.war`, `.aar`, `.zip`) trigger the scan-on-download flow. The adapter parses the group ID, artifact ID, and version from the URL path, downloads from upstream, scans, and serves or blocks.

2. **Pass-through files** are proxied directly without scanning:
   - `.pom` — POM metadata
   - `.sha1`, `.md5`, `.sha256` — checksums
   - `.asc` — GPG signatures
   - `maven-metadata.xml` — version listings

3. **Classifier support:** Artifacts with classifiers (e.g., `-sources.jar`, `-javadoc.jar`) are correctly parsed and scanned.

### Artifact ID Format

`maven:{groupId}:{artifactId}:{version}` (e.g., `maven:org.apache.commons:commons-lang3:3.14.0`)

### Security

- **Path traversal protection:** All paths are cleaned with `path.Clean()`, paths containing `..` are rejected, and all path components are validated against `^[a-zA-Z0-9._\-]+$`.
- **Upstream URL construction:** Uses `url.JoinPath()` exclusively, never string concatenation.

### Known Limitations

- **POM inspection:** POM files may contain `<repositories>` elements pointing to attacker-controlled servers. Currently proxied without inspection. Future work: POM XML validation.
- **Snapshot versions:** `1.0-SNAPSHOT` versions are proxied but cache behavior may be unexpected since snapshot builds are mutable.

### Client Configuration

```xml
<!-- settings.xml -->
<mirrors>
  <mirror>
    <id>shieldoo-gate</id>
    <url>http://shieldoo-gate:8085</url>
    <mirrorOf>central</mirrorOf>
  </mirror>
</mirrors>
```

```kotlin
// build.gradle.kts
repositories {
    maven { url = uri("http://shieldoo-gate:8085") }
}
```

## RubyGems Adapter

| | |
|---|---|
| **Package** | `internal/adapter/rubygems/` |
| **Protocol** | RubyGems API |
| **Default port** | 8086 |
| **Default upstream** | `https://rubygems.org` |
| **Compatible clients** | `gem`, `bundler` |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/gems/{name}-{version}.gem` | **Download gem** -- triggers scan if not cached |
| `GET` | `/api/v1/gems/{name}.json` | Gem metadata (JSON) -- pass-through |
| `GET` | `/api/v1/versions/{name}.json` | Version listing -- pass-through |
| `GET` | `/quick/Marshal.4.8/*` | Compressed gemspec -- pass-through |
| `GET` | `/specs.4.8.gz` | Full index -- pass-through |
| `GET` | `/latest_specs.4.8.gz` | Latest index -- pass-through |
| `GET` | `/prerelease_specs.4.8.gz` | Prerelease index -- pass-through |

### How It Works

1. **Gem downloads** (`/gems/{name}-{version}.gem`) trigger the scan-on-download flow. The adapter parses the gem name and version from the filename, downloads the `.gem` file from upstream, scans it, and either serves or blocks it.

2. **Metadata and index requests** are proxied directly to the upstream rubygems.org without scanning.

3. **Gem filename parsing** handles hyphenated gem names correctly by scanning from right to find the last hyphen followed by a digit. Platform-specific gems (e.g., `nokogiri-1.16.0-x86_64-linux.gem`) have the platform suffix stripped from the version.

### Artifact ID Format

`rubygems:{name}:{version}` (e.g., `rubygems:rails:7.1.3`, `rubygems:aws-sdk-core:3.0.0`)

### Security

- **Path traversal protection:** Filenames are validated against `^[a-zA-Z0-9._\-]+$` and checked for `..` sequences.
- **Input validation:** Package names and versions are validated using the shared `ValidatePackageName()` and `ValidateVersion()` helpers.

### Known Limitations

- **Compact index API** (`/api/v1/dependencies`, `/info/{name}`) is not yet implemented. Modern Bundler may fall back to the legacy full index API which is slower. If Bundler compatibility is critical, compact index support should be added.
- **Gem push** is not supported -- this is a read-only proxy.

### Client Configuration

```bash
# gem install
gem install rake --source http://shieldoo-gate:8086

# Gemfile
source "http://shieldoo-gate:8086"
gem "rails"
```

## Go Modules Adapter

| | |
|---|---|
| **Package** | `internal/adapter/gomod/` |
| **Protocol** | [GOPROXY Protocol](https://go.dev/ref/mod#goproxy-protocol) |
| **Default port** | 8087 |
| **Default upstream** | `https://proxy.golang.org` |
| **Compatible clients** | `go` (1.13+) |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/{module}/@v/list` | Version listing (text, one version per line) -- pass-through |
| `GET` | `/{module}/@v/{version}.info` | Version metadata (JSON) -- pass-through |
| `GET` | `/{module}/@v/{version}.mod` | go.mod file (text) -- pass-through |
| `GET` | `/{module}/@v/{version}.zip` | **Module source zip** -- triggers scan if not cached |
| `GET` | `/{module}/@latest` | Latest version info -- pass-through |

### How It Works

1. **Module path encoding:** Go module paths with uppercase characters are encoded per the GOPROXY protocol (e.g., `github.com/Foo/Bar` becomes `github.com/!foo/!bar` in URLs). The adapter uses `golang.org/x/mod/module.UnescapePath()` for decoding -- no custom encoding logic.

2. **Catch-all routing:** Module paths contain slashes (`github.com/user/repo`), so Chi's `{param}` cannot be used. The adapter uses a catch-all `/*` route and parses the path manually, finding the `/@v/` separator to split module path from action.

3. **Major version suffix:** Module paths like `github.com/user/repo/v2` are correctly handled -- the `/v2` is part of the module path, not the version.

4. **Zip downloads** (`.zip`) trigger the scan-on-download flow. The adapter downloads the module source zip from upstream, scans it, and either serves or blocks it. Blocked modules return HTTP 410 Gone (Go convention).

5. **Metadata and list requests** (`.info`, `.mod`, `list`, `@latest`) are proxied directly to the upstream without scanning.

6. **License detection:** Trivy does not support the Go ecosystem, so the adapter scans LICENSE-family files (`LICENSE`, `LICENCE`, `COPYING`, `UNLICENSE` plus common extensions like `.md`/`.txt`) at the module root inside the downloaded zip using [`google/licensecheck`](https://pkg.go.dev/github.com/google/licensecheck). Matches with ≥75% coverage are normalized to SPDX IDs, forwarded to the scanner engine via `scanArtifact.ExtraLicenses` for policy enforcement, and asynchronously persisted to `sbom_metadata` (generator `gomod-licensecheck`) so licenses appear in the admin UI and the `/licenses` API.

### Artifact ID Format

`go:{module_path}:{version}` (e.g., `go:github.com/rs/zerolog:v1.33.0`)

### Security

- **Path traversal protection:** Paths containing `..` are rejected. Control characters, null bytes, `?`, and `#` in module paths are rejected.
- **Module path decoding:** Uses `golang.org/x/mod/module.UnescapePath()` exclusively -- no custom encoding.
- **Upstream URL construction:** Uses `url.JoinPath()` exclusively, never string concatenation.

### Known Limitations

- **No sum.golang.org validation:** The adapter does not validate module checksums against Go's checksum database. Go's security model relies on `sum.golang.org` to detect tampered modules. Clients should keep `GONOSUMDB` unset to maintain checksum verification via their local `go.sum` file. Clients may need `GONOSUMCHECK=*` if the proxy serves content that differs from upstream (e.g., blocked modules).
- **No private module support:** `GOPRIVATE` patterns and Git credential forwarding are out of scope for v1.1.
- **No module publishing:** This is a read-only proxy.

### Client Configuration

```bash
# Set GOPROXY to point at Shieldoo Gate
export GOPROXY=http://shieldoo-gate:8087

# Required if Go rejects checksums from the proxy
export GONOSUMCHECK=*

# Download dependencies
go mod download
```

## Proxy Authentication (v1.1)

When `proxy_auth.enabled: true`, all proxy endpoints require an API key via HTTP Basic Auth. The password field carries the API key; the username is ignored for authentication but logged in the audit trail.

### Client Configuration with API Key

```bash
# PyPI (pip / uv)
pip install --index-url https://user:TOKEN@gate:5000/simple/ package-name
uv pip install --index-url https://user:TOKEN@gate:5000/simple/ package-name

# npm
npm config set //gate:4873/:_authToken TOKEN

# Docker
docker login gate:5002 -u user -p TOKEN

# NuGet
nuget sources add -Source https://gate:5001/v3/index.json -UserName user -Password TOKEN

# RubyGems
gem sources -a https://user:TOKEN@gate:8086/

# Go Modules
GOPROXY=https://user:TOKEN@gate:8087 go mod download

# Maven (settings.xml)
# Add <server><id>shieldoo</id><username>user</username><password>TOKEN</password></server>
```

### Key Types

| Type | Description | Management |
|---|---|---|
| **Per-user PAT** | Personal Access Token tied to OIDC user | `POST /api/v1/api-keys` (requires OIDC auth) |
| **Global token** | Shared token from env var | Set via `proxy_auth.global_token_env` config |

### TLS Requirement

Basic Auth sends credentials in base64 (not encrypted). **TLS is required** when proxy auth is enabled. Shieldoo Gate does not terminate TLS — use a reverse proxy (nginx, Caddy, Ingress controller) in front.

## Port Summary

| Ecosystem | Default Port | Docker Compose Host Port |
|---|---|---|
| PyPI | 5000 | 5010 (avoids macOS AirPlay conflict on 5000) |
| npm | 4873 | 4873 |
| NuGet | 5001 | 5001 |
| Docker | 5002 | 5002 |
| Maven | 8085 | 8085 |
| RubyGems | 8086 | 8086 |
| Go Modules | 8087 | 8087 |
| Admin API | 8080 | 8080 |
