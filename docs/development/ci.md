# Continuous Integration & Security Scanning

Shieldoo Gate uses GitHub Actions for CI. All workflow `uses:` refs are pinned
to commit SHAs ([ADR-015](../adr/ADR-015-sha-pin-github-actions.md)) and are
kept current by Dependabot (`.github/dependabot.yml`).

## Workflows

| Workflow | File | Trigger | Purpose |
|---|---|---|---|
| **CI** | `.github/workflows/ci.yml` | PR + push to `main` | Build, vet, and test the Go core; lint and build the React UI |
| **Security scan** | `.github/workflows/codeql.yml` | PR + push to `main` + weekly | CodeQL SAST (Go + TS) and `govulncheck` (Go CVEs) |
| **Scorecard** | `.github/workflows/scorecard.yml` | PR + push to `main` + weekly + `branch_protection_rule` | OpenSSF Scorecard supply-chain posture; publishes the public score behind the README badge |
| **Release** | `.github/workflows/release.yml` | tag `vX.Y.Z` | Build/push images, cross-compile `shdg`, dogfood SBOM scan, sign + attest provenance, GitHub release |

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

### Scorecard (`scorecard.yml`)

[OpenSSF Scorecard](https://github.com/ossf/scorecard) scores the repository
against supply-chain best practices (branch protection, pinned dependencies,
least-privilege token permissions, signed releases, dangerous workflow patterns,
…). For a supply-chain security tool this score is the public credibility
metric, so it is published and surfaced via the README badge.

- **Top-level `permissions: read-all`**; the analysis job widens only
  `security-events: write` (SARIF → Security tab) and `id-token: write` (OIDC
  for `publish_results`, Sigstore-backed).
- **`publish_results`** is gated to non-PR runs (`github.event_name != 'pull_request'`)
  — the public score must come from the default branch. PR runs exist only to
  prove the workflow is green before merge.
- **Triggers:** `branch_protection_rule` (re-score when protection changes, the
  highest-weighted check), weekly cron, push to `main`, and `pull_request`.
- The score is viewable at
  [scorecard.dev/viewer](https://scorecard.dev/viewer/?uri=github.com/cloudfieldcz/shieldoo-gate)
  and via deps.dev.

> A few checks (Branch-Protection, Signed-Releases) only score once the
> corresponding controls land — Branch-Protection (T9) and Signed-Releases
> (T7) are now in place; the score reflects them after the next default-branch
> run (and, for Signed-Releases, the next `vX.Y.Z` tag).

### Release signing & provenance (`release.yml`)

Every released artifact is signed and carries SLSA build provenance using
**keyless Sigstore** (Fulcio certs from the GitHub Actions OIDC token, recorded
in Rekor — no long-lived signing key). See
[ADR-018](../adr/ADR-018-build-provenance-and-signing.md) for the rationale.

- **Images** — built with `provenance: mode=max` + `sbom: true` (BuildKit
  attaches SLSA provenance + a CycloneDX SBOM as OCI referrers),
  `actions/attest-build-provenance` (GitHub-hosted provenance, pushed to the
  registry), and `cosign sign` **by digest**.
- **`shdg` binaries** — one `actions/attest-build-provenance` attestation over
  all five archives.
- **Dogfooded SBOMs** — persisted via `shdg scan --sbom-output`, attached to the
  release (`*.cdx.json`), folded into `SHA256SUMS`, and signed with
  `cosign sign-blob --bundle`. The signed bytes are the same ones uploaded to
  the gate. Fail-closed guards reject an incomplete `SHA256SUMS` or an empty SBOM.

Permissions are least-privilege: top-level `contents: read`, with each job
widening only the scopes it needs (`packages`/`id-token`/`attestations` on the
image and release jobs). New actions are SHA-pinned per
[ADR-015](../adr/ADR-015-sha-pin-github-actions.md). The release notes for each
tag embed the exact `cosign verify` / `gh attestation verify` commands.

## UI linting

ESLint uses a flat config (`ui/eslint.config.js`, ESLint 10) with the
`@eslint/js` + `typescript-eslint` recommended sets plus the canonical
Vite-React-TS hooks rules (`rules-of-hooks` = error, `exhaustive-deps` = warn).
`react-hooks` v7's newer `recommended-latest` (which adds `set-state-in-effect`)
is deliberately not adopted — that would be a separate, reviewed refactor. Run
locally with `npm run lint` from `ui/`.
