# Continuous Integration & Security Scanning

Shieldoo Gate uses GitHub Actions for CI. All workflow `uses:` refs are pinned
to commit SHAs ([ADR-015](../adr/ADR-015-sha-pin-github-actions.md)) and are
kept current by Dependabot (`.github/dependabot.yml`).

## Workflows

| Workflow | File | Trigger | Purpose |
|---|---|---|---|
| **CI** | `.github/workflows/ci.yml` | PR + push to `main` | Build, vet, and test the Go core; lint and build the React UI |
| **Security scan** | `.github/workflows/codeql.yml` | PR + push to `main` + weekly | CodeQL SAST (Go + TS) and `govulncheck` (Go CVEs) |
| **Release** | `.github/workflows/release.yml` | tag `vX.Y.Z` | Build/push images, cross-compile `shdg`, dogfood SBOM scan, GitHub release |

### CI (`ci.yml`)

Two jobs, both `permissions: contents: read`:

- **`go`** — `make build`, `make lint` (`go vet`), `make test` (`go test -race`).
  CGO is on (go-sqlite3 + `-race` require it); gcc is present on
  `ubuntu-latest`.
- **`ui`** — `npm ci`, `npm run lint` (ESLint 10 flat config), `npm run build`
  (`tsc` + Vite — the type-check gate).

> **Never set `SGW_TOKEN` / `SGW_USER` in CI.** The Makefile reroutes `GOPROXY`
> through the production gate when `SGW_TOKEN` is set, which 403s for
> unauthenticated CI and breaks `make build`.

Go and Node versions are pinned via `env:` and kept in lockstep with `go.mod`
and `docker/Dockerfile`.

### Security scan (`codeql.yml`)

- **CodeQL** — matrix over `go` and `javascript-typescript`, `security-extended`
  query suite, results uploaded to the repo **Security** tab
  (`security-events: write`). Free for this public repo — no GitHub Advanced
  Security licence required (a private repo would need GHAS).
- **govulncheck** — `golang.org/x/vuln/cmd/govulncheck` (pinned version),
  reachability-aware CVE scan against the Go vulnerability database.

The weekly schedule re-scans already-merged code so newly-disclosed CVEs still
surface.

## UI linting

ESLint uses a flat config (`ui/eslint.config.js`, ESLint 10) with the
`@eslint/js` + `typescript-eslint` recommended sets plus the canonical
Vite-React-TS hooks rules (`rules-of-hooks` = error, `exhaustive-deps` = warn).
`react-hooks` v7's newer `recommended-latest` (which adds `set-state-in-effect`)
is deliberately not adopted — that would be a separate, reviewed refactor. Run
locally with `npm run lint` from `ui/`.
