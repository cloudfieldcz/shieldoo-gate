# Shieldoo Gate — E2E Shell Tests

End-to-end test suite that validates the full Shieldoo Gate stack using real package manager clients.

## What it tests

- **PyPI** — package installation through the proxy (`uv pip install`)
- **npm** — package installation through the proxy (`npm install`)
- **NuGet** — package restore through the proxy (`dotnet restore`; skipped if `dotnet` is not installed)
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

Optional:
- `dotnet` — NuGet tests are automatically skipped when missing

## Running

```bash
./tests/e2e-shell/run.sh
```

### Flags

| Flag | Description |
|------|-------------|
| `--no-build` | Skip `docker compose build` — use already-built images |
| `--keep` | Leave the stack running after tests (useful for debugging failures) |

## Isolation

The suite uses `docker-compose.e2e.yml` (project name `shieldoo-e2e`) with dedicated ports in the `15xxx`/`18xxx` range and its own named volumes, so it does not interfere with a locally running development stack.

Teardown (including volume cleanup) happens automatically via an `EXIT` trap unless `--keep` is passed.
