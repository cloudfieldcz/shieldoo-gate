# CLI Tool & CI/CD Integration

> Developer-facing CLI tool and CI/CD pipeline plugins for pre-build supply chain checks.

**Status:** Proposed
**Priority:** High
**Perspective:** Developer Experience / DevSecOps

## Problem

Shieldoo Gate currently operates as a transparent proxy — developers interact with it indirectly through their package managers. This works well for runtime protection, but developers lack visibility into *why* a package was blocked, what the scan results look like, or how to request an override. Security feedback comes too late (build fails with a cryptic 403) and the resolution path goes through the admin UI, which most developers never see.

CI/CD pipelines similarly have no way to perform pre-merge dependency audits. A developer adds a new dependency in a pull request, and nobody knows it is malicious or vulnerable until the build actually tries to fetch it through the proxy.

## Proposed Solution

### 1. `shieldoo` CLI Tool

A standalone binary (Go, cross-platform) that communicates with the Shieldoo Gate Admin API to provide developer-facing workflows.

**Core commands:**

```bash
# Check a specific package before adding it as a dependency
shieldoo check pypi:requests:2.31.0
shieldoo check npm:lodash:4.17.21
shieldoo check docker:nginx:1.25.3

# Audit all dependencies in a project (reads lockfiles)
shieldoo audit                        # Auto-detect ecosystem from current directory
shieldoo audit --file requirements.txt
shieldoo audit --file package-lock.json
shieldoo audit --file go.sum

# View scan results for a previously scanned artifact
shieldoo inspect pypi:litellm:1.82.6

# Request an override (creates a pending request for policy-approver)
shieldoo override request pypi:somepkg:1.0.0 --reason "False positive, verified manually"

# View quarantine status
shieldoo quarantine list
shieldoo quarantine show pypi:litellm:1.82.6

# Health check
shieldoo status
```

**Authentication:** Uses PAT tokens (already implemented) stored in `~/.shieldoo/config.yaml` or `SHIELDOO_TOKEN` environment variable.

**Output formats:** Human-readable (default), JSON (`--json`), SARIF (`--sarif` for GitHub/GitLab integration).

### 2. CI/CD Pipeline Integration

**GitHub Actions:**
```yaml
- uses: shieldoo/gate-action@v1
  with:
    gate-url: https://gate.example.com
    token: ${{ secrets.SHIELDOO_TOKEN }}
    lockfiles: |
      requirements.txt
      package-lock.json
    fail-on: quarantined           # "quarantined" | "suspicious" | "any-finding"
```

**GitLab CI:**
```yaml
shieldoo-audit:
  image: ghcr.io/shieldoo/gate-cli:v1
  script:
    - shieldoo audit --fail-on quarantined --format sarif --output gl-dependency-scanning-report.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

**Jenkins, Azure DevOps, Bitbucket:** Shell-based integration using the CLI binary.

### 3. Pre-commit Hook

```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/shieldoo/gate-cli
    rev: v1.0.0
    hooks:
      - id: shieldoo-audit
        files: '(requirements.*\.txt|package.*\.json|go\.sum|Gemfile\.lock|.*\.csproj)$'
```

Detects dependency file changes in the commit and runs `shieldoo audit` against them.

### Key Requirements

1. **Zero-install option:** Provide pre-built binaries for Linux/macOS/Windows and a Docker image. The CLI should be a single static binary with no runtime dependencies.
2. **SARIF output:** Critical for integration with GitHub Advanced Security, GitLab SAST, and other code scanning platforms.
3. **Diff-aware audit:** In CI, only check *changed* dependencies (compare lockfile diff), not the entire dependency tree. Reduces API calls and runtime.
4. **Offline mode:** Cache recent check results locally so developers can work without constant API connectivity.
5. **Exit codes:** Standard exit codes (0 = clean, 1 = findings, 2 = error) for pipeline integration.

### How It Fits Into the Architecture

- **New repository:** `github.com/shieldoo/gate-cli` — standalone Go module, imports no internal packages from the main repo.
- **Admin API:** Uses existing endpoints (`GET /api/v1/artifacts`, `POST /api/v1/overrides`, etc.). May need a few new endpoints:
  - `POST /api/v1/check` — submit a package for on-demand scanning (if not already cached)
  - `POST /api/v1/audit` — batch check multiple packages from a lockfile
- **Authentication:** Uses existing PAT system. The CLI stores the token locally.

### Considerations

- **API rate limiting:** Audit commands can generate many API calls. The batch endpoint (`/api/v1/audit`) should accept a list and return results in one response.
- **On-demand scanning:** If a package has never passed through the proxy, the CLI check would need to trigger a scan. This requires the proxy to support "scan without cache" mode.
- **Versioning:** CLI and Gate API versions must be compatible. Use API versioning headers.
