# Shieldoo Gate — E2E Shell Tests

End-to-end test suite that validates the full Shieldoo Gate stack using real package manager clients.

## What it tests

- **PyPI** — package installation through the proxy (`uv pip install`)
- **npm** — package installation through the proxy (`npm install`)
- **NuGet** — package restore through the proxy (`dotnet restore`; skipped if `dotnet` is not installed)
- **Docker (smoke)** — basic `/v2/` endpoint check (proxy alive, API version header)
- **Docker Registry (comprehensive)** — multi-upstream pull, push, allowlist enforcement, tag management API, sync, scan pipeline verification
- **Admin API** — stats endpoint, audit log entries after proxy traffic

## Prerequisites

Required tools (must be on `PATH`):

| Tool | Purpose |
|------|---------|
| `docker` + compose plugin | Run the e2e stack |
| `curl` | API assertions |
| `jq` | JSON response parsing |
| `uv` | PyPI proxy tests |
| `node` / `npm` | npm proxy tests |
| `crane` | Docker registry tests (OCI image push/pull without a daemon) |

Optional:
- `dotnet` — NuGet tests are automatically skipped when missing

### Installing crane

`crane` is part of [go-containerregistry](https://github.com/google/go-containerregistry). Install via:

```bash
go install github.com/google/go-containerregistry/cmd/crane@latest
```

Or on macOS: `brew install crane`

## Running

```bash
./tests/e2e-shell/run.sh
```

### Flags

| Flag | Description |
|------|-------------|
| `--no-build` | Skip `docker compose build` — use already-built images |
| `--keep` | Leave the stack running after tests (useful for debugging failures) |

## Docker Registry Tests

The `test_docker_registry.sh` file contains comprehensive tests for the Docker registry redesign features:

### Multi-Upstream Pull

Pulls images from four registries through the gate proxy:

- **Docker Hub (default):** `hello-world`, `busybox` (bare name expansion), `alpine:3.20`
- **gcr.io:** `distroless/static`, `distroless/base`
- **ghcr.io:** `hlesey/busybox`, `umputun/baseimage/scratch`
- **cgr.dev:** `chainguard/static`, `chainguard/busybox`

### Allowlist Enforcement

Verifies that requests to disallowed registries (`evil.io`, `quay.io`) return HTTP 403 and generate BLOCKED audit entries.

### Push

Tests internal image push via `crane copy`:

- Push to internal namespace (`myteam/testapp`, `myteam/toolbox`) succeeds
- Push to upstream namespaces (`gcr.io/*`, `cgr.dev/*`) is rejected
- Pushed images can be pulled back

### Tag Management API

Tests the CRUD tag management API:

- List repositories (all, filtered by registry)
- List tags for a repository
- Create and delete tags via API
- List allowed registries endpoint

### Sync

Tests the manual sync trigger:

- POST to sync endpoint returns 202/200
- `last_synced_at` field is updated after sync completes

### Scan Pipeline

Verifies the scan pipeline ran for Docker artifacts:

- Gate logs contain scan pipeline entries
- Docker artifacts registered in API
- SCANNED audit events present
- `/v2/` returns correct response headers

## E2E Stack Architecture

The stack is defined in `docker-compose.e2e.yml` (project name `shieldoo-e2e`):

| Service | Purpose | Port |
|---------|---------|------|
| `shieldoo-gate` | Main proxy under test | 15010 (PyPI), 14873 (npm), 15001 (NuGet), 15002 (Docker), 18080 (Admin) |
| `scanner-bridge` | Python scanner sidecar (GuardDog) | Unix socket |
| `push-registry` | Local `registry:2` for push verification | 15003 |

The `push-registry` is **not** an upstream — it exists only as a local OCI registry for verifying that pushed images can be pulled back. The actual push target is `shieldoo-gate` itself.

## Isolation

The suite uses `docker-compose.e2e.yml` (project name `shieldoo-e2e`) with dedicated ports in the `15xxx`/`18xxx` range and its own named volumes, so it does not interfere with a locally running development stack.

Teardown (including volume cleanup) happens automatically via an `EXIT` trap unless `--keep` is passed.
