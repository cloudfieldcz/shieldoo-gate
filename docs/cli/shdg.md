# `shdg` — Shieldoo Gate CLI

`shdg` is a small CI helper that uploads CycloneDX SBOMs to a Shieldoo Gate
deployment for vulnerability scanning. It generates the SBOM itself (via a
pinned Trivy that it auto-downloads on first run) or accepts a pre-built file
via `--sbom`.

It is the recommended way to drive the [vulnerability-scan ingestion API](../features/vulnerability-scan.md)
from a CI pipeline.

## Install

Pre-built binaries are attached to every [GitHub release](https://github.com/cloudfieldcz/shieldoo-gate/releases)
for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`, and `windows/amd64`. Each
release ships a `SHA256SUMS` file you can feed into `sha256sum -c`.

### From GitHub Releases (recommended for CI)

With the `gh` CLI:

```bash
# Latest release
gh release download --repo cloudfieldcz/shieldoo-gate \
  --pattern 'shdg-*-linux-amd64.tar.gz' --pattern 'SHA256SUMS'

# Pinned tag (recommended — reproducible builds)
gh release download v1.2.3 --repo cloudfieldcz/shieldoo-gate \
  --pattern 'shdg-*-linux-amd64.tar.gz' --pattern 'SHA256SUMS'

sha256sum -c --ignore-missing SHA256SUMS
tar -xzf shdg-*-linux-amd64.tar.gz
sudo install -m 0755 shdg /usr/local/bin/shdg
```

Without `gh` — plain `curl` + GitHub API (handy for minimal CI images):

```bash
TAG=v1.2.3                      # pin in CI; or use /latest below
ASSET="shdg-${TAG#v}-linux-amd64.tar.gz"
curl -fsSL -o "${ASSET}" \
  "https://github.com/cloudfieldcz/shieldoo-gate/releases/download/${TAG}/${ASSET}"
curl -fsSL -o SHA256SUMS \
  "https://github.com/cloudfieldcz/shieldoo-gate/releases/download/${TAG}/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf "${ASSET}" && sudo install -m 0755 shdg /usr/local/bin/shdg
```

To resolve `/latest` programmatically:

```bash
curl -fsSL "https://api.github.com/repos/cloudfieldcz/shieldoo-gate/releases/latest" \
  | jq -r '.assets[] | select(.name|endswith("-linux-amd64.tar.gz")) | .browser_download_url' \
  | xargs curl -fsSLo shdg.tar.gz
```

### Build from source

```bash
git clone https://github.com/cloudfieldcz/shieldoo-gate.git
cd shieldoo-gate
make build-shdg
sudo cp bin/shdg /usr/local/bin/
```

The `make build-shdg` target stamps `Version` and `Commit` from `git describe`
+ `git rev-parse --short HEAD`. A static cross-build for Linux runners is the
most common form:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags "-X main.Version=$(git describe --tags --always --dirty)" \
  -o bin/shdg ./cmd/shdg
```

`shdg scan` shells out to a bundled Trivy binary on first run. The download is
pinned to **Trivy v0.71.1** with a per-platform SHA-256 list; an unrecognised
checksum fails the build closed (CLAUDE.md security invariant 4 — pinned
scanner deps).

## Subcommands

```text
shdg scan      — generate (or re-use) an SBOM and upload it
shdg version   — print version + Go runtime + OS/arch
shdg help      — short usage
```

### `shdg scan`

Generate (or re-use) a CycloneDX SBOM and upload it to the gate's
`POST /api/v1/projects/{label}/components/{name}/scans` endpoint.

| Flag | Type | Default | Notes |
|------|------|---------|-------|
| `--project` | string | — (required) | Project label as configured in the gate. |
| `--component` | string | — (required) | Logical component name. Lazy-created on first upload. |
| `--sbom` | path | (none — generate) | Skip Trivy and upload this file as-is. |
| `--image` | string | (none) | Image reference (e.g. `myorg/api:1.4.2`). Runs `trivy image <ref>` instead of `trivy fs`. Mutually exclusive with `--sbom`/`--dir`. |
| `--ecosystem` | enum | `auto` | `auto`, `pypi`, `npm`, `docker`, `go`, `multi`. With `--image` set, only `auto`, `docker`, and `multi` are allowed. |
| `--dir` | path | `.` | Project directory to scan when generating. Ignored with `--image` (error if explicitly set). |
| `--skip-dirs` | string | (none) | Comma-separated directories to skip during `trivy fs` (e.g. `examples,tests`). Forwarded as repeated `--skip-dirs` flags. No-op with `--image`/`--sbom`. |
| `--sbom-output` | path | (none) | Also write the uploaded CycloneDX SBOM to this path (parent dirs created). The bytes are byte-for-byte identical to what is POSTed to the gate, so a release pipeline can attest/sign exactly the SBOM the gate ingested. Works with any source (`--sbom`/`--image`/`--dir`). |
| `--wait` | bool | `false` | Poll `GET /api/v1/vulnerabilities/scan-runs/{id}` until terminal status. |
| `--fail-on` | enum | `none` | `critical`, `high`, `none`. Requires `--wait`. |
| `--timeout` | duration | `10m` | Wait timeout (Go duration string, e.g. `5m`, `30s`). |
| `--poll-interval` | duration | `2s` | Polling cadence when `--wait` is set. |
| `--verbose` | bool | `false` | Verbose stderr logging (logs the Trivy binary path, etc.). |

`--fail-on=critical|high` without `--wait` is a usage error (exit 2): silently
ignoring it would hide vulnerabilities and turn the CI gate into a no-op.

#### Source selection (`--sbom` / `--image` / `--dir`)

These three flags describe **what** to scan and are mutually exclusive:

| Flag | What gets scanned | When to use |
|------|-------------------|-------------|
| `--sbom path.json` | The file you point at. | You already have a CycloneDX SBOM from Syft, cyclonedx-bom, etc. |
| `--image REF` | A built container image (calls `trivy image REF`). | You ran `docker build`/`podman build` and want OS-layer coverage. |
| `--dir PATH` (default `.`) | A project directory (calls `trivy fs PATH`). | Source-tree scan — `go.sum`, `package-lock.json`, `requirements.txt`, etc. |

Passing two of them is an exit-2 usage error. Passing none defaults to `--dir .`.

#### Ecosystem resolution (precedence)

The `ecosystem` label is what the gate stores on the Component row and shows in the
`/vulnerabilities` dashboard. Resolution order, highest priority first:

1. **Explicit `--ecosystem X`** where X ∈ {`pypi`, `npm`, `docker`, `go`, `multi`} → use X. With `--image`, only `docker`/`multi` are accepted; `pypi`/`npm`/`go` are rejected because they would misrepresent the source shape.
2. **`--image` set** with `--ecosystem auto` (or unset) → `docker`.
3. **Filesystem markers in `--dir`**: `Dockerfile`/`Containerfile` → `docker`, `go.mod` → `go`, `package.json` → `npm`, `requirements.txt`/`pyproject.toml` → `pypi`.
4. **Fallback** → `multi`.

#### Scanning a built image

Use `--image` after `docker build`/`podman build` to capture both OS-layer packages
(deb/apk/rpm) **and** application dependencies. `--dir .` against a Dockerfile only
sees the build context — base-image layers are invisible.

```bash
docker build -t myorg/api:1.4.2 .
shdg scan \
  --project myorg --component api-image \
  --image myorg/api:1.4.2 \
  --wait --fail-on critical
```

Recommended practice:

- **Use a digest, not a tag, in production.** `myorg/api@sha256:...` is content-addressed and re-scans are reproducible. A floating tag (`:latest`, `:1.4.2` if you ever force-push) yields a different SBOM next month.
- **Pin a platform when it matters.** `trivy image` defaults to the runner's arch. For multi-arch images, supply a platform-specific digest so the SBOM matches what runs in production.
- **Distinct component names for source vs image.** Scanning the source tree and the built image of the same service into the same `--component` interleaves runs with very different shapes. Recommended: `api-source` (`--dir`) vs `api-image` (`--image`).
- **Expect more findings than `--dir`.** Image scans surface OS-layer CVEs that filesystem scans never see. Many will be "won't-fix" or low-priority in the upstream distro. Pin a baseline (or use per-component ignores) before enabling `--fail-on critical` in a blocking CI gate.
- **Private registries.** Trivy reads `~/.docker/config.json` automatically. Run `docker login` (or write the config file) before `shdg scan`. On shared / persistent CI runners, scope it per-job with `DOCKER_CONFIG=$(mktemp -d)` to avoid one job's credentials leaking to another.
- **Network egress.** `--image REF` makes outbound HTTPS to the registry implied by `REF`. CI runners with restricted egress need to be whitelisted accordingly.
- **First-run cost.** The bundled Trivy downloads its vulnerability DB (~30–50 MiB) into `~/.cache/trivy` on the first `--image` invocation. Cache this directory in CI (`actions/cache` on GitHub, equivalent on GitLab) to skip the cost on subsequent runs.

### `shdg version`

Prints `shdg <version> (<commit>) — <go-version> <os>/<arch>`. Stamped at
build time via `-ldflags "-X main.Version=...  -X main.Commit=..."`. Unset
builds report `dev (unknown)`.

## Environment

| Env | Default | Notes |
|-----|---------|-------|
| `SHIELDOO_TOKEN` | — | PAT carrying the `scan:upload` scope (or the global super-token). Required for `scan`. |
| `SHIELDOO_URL` | — | Base URL of the gate (e.g. `https://gate.example.com`). Required for `scan`. |
| `SHDG_CACHE_DIR` | `~/.cache/shdg` | Override the Trivy binary cache directory. The pinned binary lives at `<cache-dir>/trivy-0.71.1/trivy`. |

Tokens are passed verbatim as `Authorization: Bearer ...` to both the upload
and polling endpoints.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Upload accepted (and, when `--wait` is set, the scan finished within `fail-on` policy). |
| `1` | Generic execution error (network, file I/O, gate 5xx) **or** `--fail-on critical/high` matched. |
| `2` | CLI / configuration error (missing required flags, invalid ecosystem, missing env). |
| `3` | Scan run reached terminal status `failed`. |
| `4` | `--wait` polling timed out before the scan reached a terminal status. |

These map exactly to `cmd/shdg/scan.go:executeScan` and `cmd/shdg/poll.go:exitCodeFor`.

## Examples

### CI gate — fail on new criticals

GitHub Actions:

```yaml
- name: Vuln scan
  env:
    SHIELDOO_TOKEN: ${{ secrets.SHIELDOO_TOKEN }}
    SHIELDOO_URL: https://gate.example.com
  run: |
    shdg scan \
      --project myproj \
      --component web \
      --wait \
      --fail-on critical \
      --timeout 5m
```

GitLab CI:

```yaml
scan:
  image: cloudfieldcz/shdg:latest   # or build-from-source step
  script:
    - shdg scan --project myproj --component web --wait --fail-on critical
  variables:
    SHIELDOO_URL: https://gate.example.com
  # SHIELDOO_TOKEN injected as a CI/CD secret
```

### Plain SBOM upload — no scan generation

```bash
trivy fs --format cyclonedx --output sbom.json .
SHIELDOO_TOKEN=$TOKEN \
SHIELDOO_URL=https://gate.example.com \
  shdg scan --project myproj --component web --sbom sbom.json
```

`--sbom` skips the bundled Trivy entirely — useful when the CI image already
ships an SBOM generator (Syft, cyclonedx-bom, custom build tooling).

### Equivalent raw curl

The CLI is a convenience wrapper. The same upload happens over plain curl:

```bash
trivy fs --format cyclonedx --output sbom.json .
curl -fsS -X POST \
  -H "Authorization: Bearer $SHIELDOO_TOKEN" \
  -H "Content-Type: application/vnd.cyclonedx+json" \
  --data-binary @sbom.json \
  https://gate.example.com/api/v1/projects/myproj/components/web/scans
```

Use the curl form when adding a binary to the CI image is undesirable; reach
for `shdg` when you want auto-detection, polling, and a single
non-zero-on-criticals exit code.

## See also

- [Vulnerability scan feature doc](../features/vulnerability-scan.md) — server-side ingestion pipeline + REST API.
- [`docs/configuration.md`](../configuration.md#shdg-cli-runtime) — env var reference.
- [`docs/api/openapi.yaml`](../api/openapi.yaml) — `POST /api/v1/projects/{label}/components/{name}/scans` and `GET /api/v1/vulnerabilities/scan-runs/{id}` definitions.
