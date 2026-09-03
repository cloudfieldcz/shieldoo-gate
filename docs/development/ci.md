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

Three jobs, all `permissions: contents: read`:

- **`go`** — a "Trivy version parity" grep check (below), `make build`,
  `make lint` (`go vet`), `make test` (`go test -race`). CGO is on
  (go-sqlite3 + `-race` require it); gcc is present on `ubuntu-latest`.
- **`ui`** — `npm ci`, `npm run lint` (ESLint 10 flat config), `npm run build`
  (`tsc` + Vite — the type-check gate).
- **`ui-e2e`** — `make test-ui`: brings up a dedicated fresh open-mode gate and
  runs the standalone Playwright suite (visual regression + interaction flows)
  inside the pinned Playwright container, diffing against the committed
  baselines. On failure it uploads the Playwright HTML report as an artifact.
  See [UI Test Suite](ui-e2e.md).

> **Never set `SGW_TOKEN` / `SGW_USER` in CI.** The Makefile reroutes `GOPROXY`
> through the production gate when `SGW_TOKEN` is set, which 403s for
> unauthenticated CI and breaks `make build`.

Go and Node versions are pinned via `env:` and kept in lockstep with `go.mod`
and `docker/Dockerfile`.

#### Trivy version lockstep

Trivy is pinned in two independent places with no shared automation:
`docker/Dockerfile`'s `FROM aquasec/trivy:...` line (the gate's bundled
binary) and `cmd/shdg/trivy.go`'s `trivyVersion` constant (what the `shdg`
CLI downloads at first run, alongside its own per-platform SHA-256 pins).
Because Dependabot only ever proposes the Docker tag bump, a routine
single-concern merge of that PR would silently leave `trivyVersion` behind —
there is no test or doc to catch it on its own. The `go` job's "Trivy version
parity" step greps both files and fails the build if the versions disagree,
so a bump must always land as one commit that moves both. When bumping,
also verify the four `expectedChecksums` entries in `cmd/shdg/trivy.go` by
downloading the real release tarballs and hashing them — never trust the
upstream `checksums.txt` alone (see the comment above `expectedChecksums`).

#### Runtime-stage OS package upgrades

Both release Dockerfiles pin their base image by digest
([ADR-014](../adr/ADR-014-base-image-digest-pinning.md)) but also run an
upgrade of already-installed OS packages in the runtime stage, on top of that
pinned base: `docker/Dockerfile`'s `apk upgrade --no-cache` (gate, alpine) and
`scanner-bridge/Dockerfile`'s `apt-get upgrade -y` (scanner-bridge, Debian).
This **does** widen what the runtime layer can pull in at build time — for
`docker/Dockerfile` it now covers the entire installed base set, not just the
two packages `apk add` itself installs — and that is a deliberate trade-off,
not a false one: security currency, bought at the cost of byte-for-byte
reproducibility of the OS layer, same framing as
[ADR-010](../adr/ADR-010-base-image-security-patching.md)'s Consequences. What
bounds the widened surface is that both package managers verify fetched
package signatures against the distro keys baked into the pinned base image
(`/etc/apk/keys` for apk, the base image's APT keyring for apt), fetched over
HTTPS — the base digest pin is not what's doing the integrity work here, the
package manager's own signature check is. On a build that actually executes
this layer, the upgrade picks up OS-security fixes published after the base
tag was cut (e.g. `libssl3`/`libcrypto3` in alpine's `v3.24` repo) instead of
waiting for the next base-tag bump. See ADR-010 for the full rationale and the
`perl-base` force-purge that goes with it on the scanner-bridge side.

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
- **Scorecard-compatible assets** — because OpenSSF Scorecard's `Signed-Releases`
  check only reads release *assets* by filename suffix (and doesn't recognise
  ghcr referrers, the attestations API, or `.cosign.bundle`), each archive +
  `SHA256SUMS` also ships a detached `*.sig` + `*.pem`, and the binary provenance
  is republished as `shdg-<ver>.intoto.jsonl`. Same keyless Sigstore material,
  scanner-readable names. See [ADR-018](../adr/ADR-018-build-provenance-and-signing.md).

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

## Held-back dependencies

Dependencies deliberately **pinned below the version Dependabot wants to move
them to** — usually a major, sometimes only a minor (the scanner-bridge base
image is held inside major 3) — with the condition that releases the hold. Each
has a matching `ignore:` entry in
[`.github/dependabot.yml`](../../.github/dependabot.yml) so the bot stops
reopening an unmergeable PR on every release. Check that entry's
`update-types` when adding a row: it must match the kind of bump actually being
blocked, which is not always the semver level it looks like (a docker tag bump
`3.13.14` -> `3.14.7` is a *minor*, not a major).

| Dependency | Pinned at | Blocked by | Release condition |
|---|---|---|---|
| `typescript` | 6.0.3 | `typescript-eslint` (incl. its canary) declares `peer typescript >=4.8.4 <6.1.0`, so TS 7 fails `npm ci` with `ERESOLVE` and leaves the type-aware lint rules without a supported parser | `typescript-eslint`'s peer range admits 7.x |
| `python` (scanner-bridge base image) | 3.13.14-slim | `guarddog` (all releases through 3.2.0, and `main`) constrains `pygit2 >=1.11,<1.19`, and `pygit2` ships `cp314` wheels only from 1.19.0 on. On 3.14 `uv` falls back to the pygit2 sdist, which links the builder's `libgit2-dev`; that `.so` is absent from the runtime stage (ADR-010), so the image fails its build-time import check with `libgit2.so.1.9: cannot open shared object file` (#184) | a `guarddog` release that allows `pygit2 >=1.19` |

Removing a hold means deleting the `ignore:` entry **and** the row above in the
same PR.
