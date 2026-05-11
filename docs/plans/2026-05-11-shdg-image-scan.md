# shdg image scan — Native built-image scanning via `--image` flag

## Overview

Today `shdg scan` always runs `trivy fs <dir>` against a project directory, regardless of the `--ecosystem` flag. For a Docker/OCI workload that means scanning the **build context** (source tree + Dockerfile) instead of the **built image**, which silently omits OS-layer packages (deb/apk/rpm) baked into base layers and any tooling installed during `RUN` steps. The server pipeline already accepts CycloneDX SBOMs from `trivy image` — only the CLI ergonomics are missing.

This change adds an `--image <ref>` flag to `shdg scan`. When set, `shdg` calls `trivy image --format cyclonedx --output <tmp> <ref>` instead of `trivy fs`, defaults the ecosystem tag to `docker`, and uploads the resulting SBOM through the existing endpoint. Output lands in the same `/vulnerabilities` dashboard as today's pypi/npm/go scans — the server treats both SBOM shapes identically.

Cross-check review (2026-05-11) surfaced four pre-existing perf gaps that `--image` materially exposes (image SBOMs are ~10× larger than fs SBOMs and produce ~10× more CVE matches). Those fixes ride with this change as Phase 2 + Phase 3. A separate subprocess-hardening PR will follow.

### Why

- **Closes a real coverage gap.** Today a CI pipeline that runs `shdg scan --ecosystem docker` on a repo with a Dockerfile produces a *build-context* SBOM that misses ~80–90 % of the actual attack surface (base-image layers). Users assume the opposite.
- **Parity with other ecosystems.** `shdg scan` for `pypi`/`npm`/`go` already runs the right Trivy command for the source-tree case. Docker is the outlier.
- **Documentation hint already promises this shape.** [`docs/features/vulnerability-scan.md:18`](../features/vulnerability-scan.md#L18) literally tells users to run `trivy image --format cyclonedx ...` and upload — `shdg` should be the one-liner that does it.
- **Existing perf gaps would silently surface as `--image` regressions.** The dev review found that the 60s client upload timeout, the 10 MiB server SBOM cap, the unbounded server scan fan-out, and a broken OSV per-vuln cache all sit comfortably above today's `trivy fs` workload but fail visibly the first time someone uploads a real image SBOM. Bundling those fixes here means the feature lands functional from day one.

## Current state

### CLI invocation path

- [`cmd/shdg/main.go:24`](../../cmd/shdg/main.go#L24) dispatches `scan` → `runScan` in [`cmd/shdg/scan.go:71`](../../cmd/shdg/scan.go#L71).
- Flag parsing: [`cmd/shdg/scan.go:32-69`](../../cmd/shdg/scan.go#L32-L69) — current flags are `--project`, `--component`, `--sbom`, `--ecosystem`, `--dir`, `--verbose`, `--wait`, `--fail-on`, `--timeout`, `--poll-interval`.
- Ecosystem resolution: [`cmd/shdg/ecosystem.go:39`](../../cmd/shdg/ecosystem.go#L39) (`resolveEcosystem`) — explicit value wins, else `detectEcosystem` looks for `Dockerfile`, `Containerfile`, `go.mod`, `package.json`, `requirements.txt`, `pyproject.toml`.
- SBOM generation: [`cmd/shdg/scan.go:169-197`](../../cmd/shdg/scan.go#L169-L197) (`generateSBOM`) — shells out to bundled Trivy with `trivy fs --format cyclonedx --quiet --output <tmp> <dir>`, then reads the tempfile back. Empty-output regression guard at line 193.
- Upload: [`cmd/shdg/upload.go:34`](../../cmd/shdg/upload.go#L34) — POSTs SBOM to `/api/v1/projects/{label}/components/{name}/scans?ecosystem=...`. The `ecosystem` query param is the only signal of the source shape; **the server treats it as a label only**.
- Trivy bootstrap: [`cmd/shdg/trivy.go:83`](../../cmd/shdg/trivy.go#L83) (`ensureTrivy`) — downloads the pinned v0.70.0 tarball, SHA-256-verifies against the per-platform pin, extracts the `trivy` binary into `<cache-dir>/trivy-0.70.0/trivy`. Reused for `trivy fs`; reused as-is for `trivy image`.

### Server ingestion path

- Route: [`internal/api/scan_upload.go:17`](../../internal/api/scan_upload.go#L17) (`handleScanUpload`).
- Ecosystem handling: [`internal/api/scan_upload.go:47-50`](../../internal/api/scan_upload.go#L47-L50) — query-param value is stored on the lazily-created Component row; defaults to `multi`. The downstream `ScanService.Submit` (line 70) consumes the raw SBOM body and does not branch on ecosystem.
- This confirms a `trivy image` CycloneDX SBOM is identically processed — same OSV+Trivy parallel scan, same aggregation, same dashboard surface.

### Comparison

| Aspect | Current state | Proposed state |
|---|---|---|
| Scan source for Docker | `trivy fs <dir>` against build context | `trivy image <ref>` against the **built** image |
| OS-layer packages (deb/apk/rpm) | Not captured | Captured |
| `--ecosystem docker` semantic | Label only; behavior identical to `--ecosystem pypi` | Label still passed through; with `--image` it auto-defaults to `docker` |
| `--image` flag | N/A | New string flag; mutually exclusive with `--sbom` |
| Output dashboard | `/vulnerabilities` | `/vulnerabilities` (identical) |
| Server changes | N/A | None |
| Trivy binary | Bundled pinned v0.70.0 (download + SHA-256 pin) | Same binary, different subcommand |

## Proposed solution

### Architecture

```
shdg scan --image myorg/api:1.4.2 --project P --component C
   │
   ├── parseScanFlags     (new --image flag; validates exclusivity vs --sbom/--dir)
   ├── resolveEcosystem    (when --image set + --ecosystem=auto → returns "docker")
   ├── ensureTrivy         (unchanged — same pinned binary)
   ├── generateImageSBOM   (NEW — `trivy image --format cyclonedx --quiet --output <tmp> <ref>`)
   └── uploadSBOM          (unchanged — same endpoint, ecosystem query param passed verbatim)
```

The SBOM shape produced by `trivy image` is a superset of `trivy fs` (adds OS-layer components). The server is shape-agnostic; the existing aggregation in `ScanService` consumes whichever CycloneDX document it gets.

### Flag interactions

| Flags supplied | Behaviour | Exit code |
|---|---|---|
| `--image REF` | Run `trivy image REF`; ecosystem auto-resolves to `docker` | 0 |
| `--image REF --ecosystem docker\|multi\|auto` | Run `trivy image REF`; ecosystem tag respected | 0 |
| `--image REF --ecosystem pypi\|npm\|go` | **Error** — label would misrepresent the source shape | 2 |
| `--image REF --sbom PATH` (user-supplied) | **Error** — pick one source | 2 |
| `--image REF --dir PATH` (user-supplied) | **Error** — `--dir` is meaningless when scanning an image | 2 |
| `--sbom PATH` | Existing: skip Trivy entirely | 0 |
| Neither | Existing: `trivy fs --dir <dir>` | 0 |

The dual-flag errors come from `parseScanFlags`, before any network or subprocess work — fail fast, just like the existing `--fail-on requires --wait` guard.

#### `--dir` default-vs-user-supplied disambiguation

`--dir` defaults to `"."` (existing behaviour at [`cmd/shdg/scan.go:40`](../../cmd/shdg/scan.go#L40)). The exclusivity check for `--image` + `--dir` must distinguish "user set `--dir`" from "default value." We use `fs.Visit` after `fs.Parse` to capture the set of user-supplied flag names, then key the exclusivity check off that set rather than off `opts.dir != ""`. Same approach applies to `--sbom` (already empty-string default, so no ambiguity there).

#### Ecosystem precedence (one canonical rule)

1. **Explicit `--ecosystem X`** where X ∈ {`pypi`, `npm`, `docker`, `go`, `multi`} → use X (subject to the `--image` compatibility check above).
2. **`--image` set** with `--ecosystem auto` or unset → `docker`.
3. **Filesystem markers in `--dir`** (`Dockerfile`/`Containerfile` → `docker`, `go.mod` → `go`, `package.json` → `npm`, `requirements.txt`/`pyproject.toml` → `pypi`) → matched ecosystem.
4. **Fallback** → `multi`.

Same rule documented verbatim in `docs/cli/shdg.md`.

### Service layer changes

Two narrow additions to `cmd/shdg/scan.go`. No new files, no new packages.

```go
// scanOpts gains:
type scanOpts struct {
    // ...existing fields...
    image string // NEW: image reference (e.g. "myorg/api:1.4.2" or "ghcr.io/...@sha256:...")
}

// generateImageSBOM is the trivy-image equivalent of generateSBOM. Same
// tempfile-then-read pattern (the 0.70.0 stdout regression also affects
// `trivy image --output -`).
func generateImageSBOM(trivyBin, imageRef string) ([]byte, error)
```

`resolveEcosystem` gains a single behaviour change: when `explicit == "auto" || explicit == ""` AND the caller indicates an image scan, return `"docker"` without filesystem inspection. Cleanest implementation: `resolveEcosystem` becomes `resolveEcosystem(explicit, dir, hasImage bool)` — three callers in `executeScan`, mechanical to update.

### Ecosystem detection updates

[`cmd/shdg/ecosystem.go:39`](../../cmd/shdg/ecosystem.go#L39) — extend signature so `--image` skips the `os.Stat(filepath.Join(dir, ...))` markers entirely. Validation of an explicit `--ecosystem` value is unchanged.

### Image reference validation

Trivy itself validates the reference, but we add a lightweight syntactic guard in `parseScanFlags` to surface a CLI error (rc=2) rather than a Trivy exec error (rc=1) for the common typos:

- Reject empty string.
- Reject leading `-` (would be parsed as a flag by Trivy).
- Reject embedded NUL or newline characters.

We do **not** parse the OCI reference grammar — Trivy is the source of truth there and a regex would either be too strict (rejecting valid tags) or too loose (no protection added).

### Database changes

None.

### UI changes

None. The new SBOM appears in `/vulnerabilities/components/:id` with `ecosystem = "docker"`, indistinguishable from a manually-uploaded `trivy image` SBOM today.

### Configuration

**Client (no change for Phase 1):** `SHIELDOO_TOKEN`, `SHIELDOO_URL`, and `SHDG_CACHE_DIR` apply unchanged.

For private registries, Trivy reads `~/.docker/config.json` automatically (its standard behaviour). We document this rather than add a `--registry-auth` flag — if users need it, they `docker login` (or write the config file) before invoking `shdg scan`.

**Server (Phases 2 + 3):** three new Viper keys, all backwards-compatible (defaults match new headroom):

| Key | Default | Effect |
|---|---|---|
| `vuln_scan.sbom.max_bytes` | `524288000` (500 MiB) | Server-side cap on uploaded SBOM body size. |
| `vuln_scan.sbom.max_components` | `500000` | Server-side cap on CycloneDX component count. |
| `vuln_scan.max_concurrent_scans` | `4` | Semaphore bound around `ScanService.Run` goroutines (upload + rescan). |

### Performance considerations

- `trivy image <ref>` for a remote reference performs a registry pull of manifests + filesystem layers it has to inspect. First-time scans of large multi-arch images can take 30 s – 5 min and several hundred MB of network. The existing `--timeout 10m` default for `--wait` is unaffected (timeout is for **server-side** scan polling, not the Trivy invocation).
- `trivy image <ref>` against a local Docker daemon (`docker pull` already done) is dominated by layer extraction — typically 10–60 s for a typical app image.
- **Trivy vulnerability DB cold-start.** The first `trivy image` invocation on a fresh runner downloads the Trivy vulnerability DB (~30–50 MiB compressed) into `~/.cache/trivy`. Cache that directory in CI to skip the cost on subsequent runs. Documented in `docs/cli/shdg.md`.
- **Per-CI-run cost is one Trivy invocation;** we do not cache the resulting SBOM client-side (server keeps history).
- **Image SBOM upload size.** Realistic image SBOMs land at 1.5–5 MiB for typical app images; large multi-language fat images can exceed 10 MiB. Phase 2 raises both the client upload timeout (60 s → 5 min) and the server-side cap (10 MiB → 500 MiB) to remove this as a silent rejection vector.
- **Server-side scan parallelism.** Phase 3 caps concurrent `ScanService.Run` goroutines at 4 (configurable). Excess uploads queue rather than fan out; the existing 202 response semantics are preserved. The OSV per-vuln cache fix in the same phase cuts hydrate-call counts by ~50–90 % on repeated scans of similar images, which is the dominant network-IO contributor for image SBOMs (10× more CVE matches than fs SBOMs).
- **Rate-limiting.** `cmd/shdg/upload.go` already retries on HTTP 429 with `Retry-After` honoured (clamped to [1 s, 60 s]). For CI fleets that share a single PAT across many parallel jobs, the existing `uploads_per_hour=60, burst=10` per-token bucket may bottleneck — operators may want to provision per-team PATs. Out of scope for this PR but documented in `docs/cli/shdg.md`.

## Affected files

### New files

None. The implementation is small enough to stay within the existing `cmd/shdg` files.

### Modified files

#### Phase 1 (client `--image` flag)

- [`cmd/shdg/scan.go:15-28`](../../cmd/shdg/scan.go#L15-L28) — add `image` field to `scanOpts`.
- [`cmd/shdg/scan.go:32-69`](../../cmd/shdg/scan.go#L32-L69) — register `--image` in `parseScanFlags`; ecosystem-compatibility check (reject `--image` + `pypi`/`npm`/`go`); `fs.Visit`-based exclusivity checks (`--image` vs user-supplied `--sbom`/`--dir`); syntactic validation.
- [`cmd/shdg/scan.go:87-159`](../../cmd/shdg/scan.go#L87-L159) — in `executeScan`, branch SBOM acquisition: `opts.sbomPath != ""` (existing) → `opts.image != ""` (NEW `generateImageSBOM`) → fallback `generateSBOM` against `opts.dir` (existing).
- [`cmd/shdg/scan.go:161-197`](../../cmd/shdg/scan.go#L161-L197) — add `generateImageSBOM` next to existing `generateSBOM`; same tempfile pattern; same empty-output guard.
- [`cmd/shdg/ecosystem.go:39-47`](../../cmd/shdg/ecosystem.go#L39-L47) — extend `resolveEcosystem` signature → `(explicit, dir string, hasImage bool)`; auto-return `"docker"` when `hasImage` is true and explicit is `"auto"`/empty.
- [`cmd/shdg/scan_test.go`](../../cmd/shdg/scan_test.go) — add cases for `--image` happy path, `--image` + `--sbom` (user-supplied) rejection, `--image` + `--dir` (user-supplied) rejection, `--image` + `--ecosystem pypi` rejection, image-ref typo rejection, ecosystem auto-resolution, default-`--dir`-with-`--image` *not* triggering exclusivity (regression guard).
- [`cmd/shdg/ecosystem_test.go:39-99`](../../cmd/shdg/ecosystem_test.go#L39-L99) — update `resolveEcosystem` callers to new signature; add `TestResolveEcosystem_ImageDefaultsToDocker` and `TestResolveEcosystem_ImageExplicitOverride`.
- [`cmd/shdg/main.go:38-51`](../../cmd/shdg/main.go#L38-L51) — update `usage()` text to mention `--image`.
- [`docs/cli/shdg.md`](../cli/shdg.md) — new flag-table row; new "Scanning a built image" section with: (a) naming guidance ("source-tree and image scans of the same service should use distinct `--component` names — e.g. `api-source` vs `api-image`"), (b) tag-vs-digest recommendation ("use `myorg/api@sha256:...` for production scans so re-scans are reproducible"), (c) Trivy DB cache note ("first `--image` invocation may download ~30–50 MiB of vulnerability DB to `~/.cache/trivy`; cache this directory in CI to skip on subsequent runs"), (d) outbound-registry-egress callout ("`--image` makes a network connection to the registry implied by the ref"). Ecosystem-precedence table copied from this analysis.
- [`docs/features/vulnerability-scan.md:18`](../features/vulnerability-scan.md#L18) — replace the manual `trivy image` snippet with `shdg scan --image <ref>`.
- [`tests/e2e-shell/test_vuln_scan_shdg.sh`](../../tests/e2e-shell/test_vuln_scan_shdg.sh) — add two `--image` sub-tests, both gated on `command -v docker` (so the test rig without a Docker daemon falls through to `log_skip`). See **Testing** section for sub-test A and B details.

#### Phase 2 (envelope sizing)

- [`cmd/shdg/upload.go:50`](../../cmd/shdg/upload.go#L50) — `http.Client{Timeout: 60 * time.Second}` → `5 * time.Minute`.
- [`internal/component/sbom_validate.go:21-28`](../../internal/component/sbom_validate.go#L21-L28) — `DefaultSBOMLimits()` returns `{MaxBytes: 500 << 20, MaxComponents: 500000}`.
- `internal/config/config.go` (or wherever Viper keys live — see [`internal/config/`](../../internal/config)) — add `vuln_scan.sbom.max_bytes` and `vuln_scan.sbom.max_components` keys defaulting to the new constants.
- [`docs/configuration.md`](../configuration.md) — document the two new Viper keys.

#### Phase 3 (server scan-concurrency + OSV hydrate cache)

- [`internal/api/scan_upload.go:86-88`](../../internal/api/scan_upload.go#L86-L88) — wrap `go ScanService.Run(...)` in `golang.org/x/sync/semaphore` acquire/release.
- [`internal/api/rescan.go`](../../internal/api/rescan.go) — same semaphore around the rescan path; share the semaphore instance via `Server`.
- `internal/api/server.go` — initialize the semaphore from `cfg.VulnScan.MaxConcurrentScans` (default 4).
- `internal/config/config.go` — add `vuln_scan.max_concurrent_scans` Viper key.
- [`internal/scanner/manifest/osv/osv.go:316-321`](../../internal/scanner/manifest/osv/osv.go#L316-L321) — fix `hydrate` cache: return cached entry when present and unexpired; write fresh fetches under `cacheMu`.
- `internal/scanner/manifest/osv/osv_test.go` — add `TestHydrate_CacheHit_NoNetworkFetch`.
- Prometheus metric `vuln_scan_queue_depth` (semaphore current value) — wire next to existing vuln-scan metrics.
- [`docs/configuration.md`](../configuration.md) — document the new key.
- [`docs/features/vulnerability-scan.md`](../features/vulnerability-scan.md) — note the new concurrency cap.

### Unchanged files (important)

- [`cmd/shdg/upload.go`](../../cmd/shdg/upload.go) — no change. The endpoint and the `ecosystem` query param are unchanged.
- [`cmd/shdg/poll.go`](../../cmd/shdg/poll.go) — `--wait`/`--fail-on` polling is decoupled from SBOM source.
- [`cmd/shdg/trivy.go`](../../cmd/shdg/trivy.go) — same pinned binary; `trivy image` is a subcommand of the same binary, no second download.
- [`internal/api/scan_upload.go`](../../internal/api/scan_upload.go) — server is shape-agnostic; the `trivy image` SBOM rides the same path.
- [`internal/component/`](../../internal/component) — ecosystem string is opaque; "docker" is already a valid value.
- [`ui/`](../../ui) — same Component view, same scan-run detail.

## Implementation phases

Three small phases that each end in a green build + test. Each phase is independently shippable in principle, but they land in one PR because Phase 2 + 3 are what make Phase 1 functionally complete for realistic image SBOMs.

### Phase 1: `--image` flag end-to-end (client-side)

- Add `image` field to `scanOpts`; register `--image` flag.
- Use `fs.Visit` post-`fs.Parse` to detect user-supplied `--dir` / `--sbom` for the exclusivity checks.
- Hard-reject `--image` combined with `--ecosystem` in `{pypi, npm, go}`; allow `auto`/`docker`/`multi`.
- Add image-ref syntactic guard (empty / NUL / newline). Leading-`-` handled in Phase 4 (subprocess hardening PR) via `--` argv separator; for now we reject leading `-` as a syntactic guard since this PR does not change the `exec.Command` invocation shape.
- Add `generateImageSBOM(trivyBin, imageRef)` mirroring `generateSBOM` (same tempfile + empty-byte guard).
- Branch `executeScan` SBOM acquisition: `opts.sbomPath != ""` (existing) > `opts.image != ""` (NEW) > fallback `generateSBOM(opts.dir)` (existing).
- Update `resolveEcosystem` signature → `(explicit, dir string, hasImage bool)`; auto-return `"docker"` when `hasImage && explicit ∈ {"", "auto"}`. Update three call sites (one in `executeScan`, two in tests).
- Update CLI usage text in [`cmd/shdg/main.go:38-51`](../../cmd/shdg/main.go#L38-L51).
- Unit tests as listed in **Testing** below.
- Docs: `docs/cli/shdg.md` (full new "Scanning a built image" section with naming guidance + tag-vs-digest recommendation + Trivy-DB-cache note) and `docs/features/vulnerability-scan.md:18` (replace the manual-`trivy image` snippet with the new `shdg scan --image` one-liner).
- E2E shell smoke test: `tests/e2e-shell/test_vuln_scan_shdg.sh` gains the two sub-tests in **Testing** below.

Expected outcome: `shdg scan --image alpine:3.20 --project p --component c` produces a CycloneDX SBOM and posts it to the gate; user sees a new scan run in the `/vulnerabilities` dashboard with OS packages listed.

Dependencies: none. The bundled Trivy v0.70.0 already supports `trivy image`.

Checklist:
- [ ] `--image` flag parsed and validated
- [ ] `--dir` / `--sbom` exclusivity uses `fs.Visit`, not value-equality
- [ ] Hard-reject `--image` with `--ecosystem` in `{pypi, npm, go}` (rc=2)
- [ ] `generateImageSBOM` shells out to `trivy image --format cyclonedx --quiet --output <tmp> <ref>`
- [ ] Empty-byte SBOM guard (mirror of [`cmd/shdg/scan.go:193`](../../cmd/shdg/scan.go#L193))
- [ ] Image-ref syntactic guard (empty / NUL / newline / leading `-`)
- [ ] `resolveEcosystem(explicit, dir, hasImage)` auto-returns `"docker"` when `hasImage` is true
- [ ] Unit tests pass (`go test ./cmd/shdg/...`)
- [ ] E2E shell sub-test A (`--image alpine:3.20`, `--fail-on none`) passes with rc=0 when `docker` is present, skips cleanly otherwise
- [ ] E2E shell sub-test B (`--image alpine:3.10`, `--fail-on critical`) returns rc=1 when OSV is reachable, tolerates rc=0 with `log_skip` when OSV is offline
- [ ] `docs/cli/shdg.md` and `docs/features/vulnerability-scan.md` updated; ecosystem precedence table added
- [ ] `make build && make lint && make test` clean

### Phase 2: Right-size the client/server SBOM envelope

Image SBOMs are an order of magnitude larger than fs SBOMs, both in bytes and component count. Today's caps were sized for fs scans and would silently reject realistic image workloads.

- **Client upload timeout** ([`cmd/shdg/upload.go:50`](../../cmd/shdg/upload.go#L50)): raise `http.Client{Timeout: 60 * time.Second}` to `5 * time.Minute`. Rationale: a 50 MiB SBOM over a 1 Mbps CI uplink is ~7 min of body transmission; even a 10 MiB upload is borderline at 60 s. The server's `MaxBytesReader` still caps the body, so a longer client deadline cannot be abused.
- **Server SBOM size cap** ([`internal/component/sbom_validate.go:21-28`](../../internal/component/sbom_validate.go#L21-L28)): raise `DefaultSBOMLimits().MaxBytes` from 10 MiB to **500 MiB**. Raise `MaxComponents` proportionally from 10000 to **500000**. Update the constant default; expose both via `cfg.VulnScan.SBOM.MaxBytes` / `MaxComponents` (Viper key) so a deployment can tune downwards if needed.
- **Memory implications.** With burst=10 concurrent uploads × 500 MiB, the theoretical worst-case resident-memory budget is 5 GiB. Mitigations:
  - Phase 3's scan-concurrency semaphore caps how many of those uploads can be **scanning** at once (the larger memory consumer); reception itself streams to disk.
  - Document the new sizing in `docs/configuration.md` (vuln-scan section).
  - Consider — not in this PR — switching `Submit`'s `ReadAllLimited` to a streaming SHA-256 + tempfile write so the SBOM is never resident in full. Tracked as a separate optimization.

Checklist:
- [ ] Client `http.Client.Timeout` raised to 5 min
- [ ] `DefaultSBOMLimits()` returns `{MaxBytes: 500 MiB, MaxComponents: 500000}`
- [ ] Viper keys `vuln_scan.sbom.max_bytes` / `vuln_scan.sbom.max_components` wired with the above as defaults
- [ ] `docs/configuration.md` updated with the new keys
- [ ] Existing tests still pass; new test that an SBOM at 11 MiB (which would have failed before) now succeeds

### Phase 3: Server scan-concurrency + OSV vuln-detail cache

Both items are pre-existing pathologies that fs-shaped SBOMs masked. Bundling them in this PR keeps `--image`'s first day of life from being a stress test of the underlying bugs.

- **Server scan-concurrency semaphore.** [`internal/api/scan_upload.go:86-88`](../../internal/api/scan_upload.go#L86-L88) spawns one goroutine per upload via `go func() { ScanService.Run(...) }()` with no bound. Wire `golang.org/x/sync/semaphore` (already in the approved dep list per CLAUDE.md) around `ScanService.Run`. Same treatment for the rescan path at [`internal/api/rescan.go:17`](../../internal/api/rescan.go#L17). Default cap **4 concurrent scans**, tunable via `cfg.VulnScan.MaxConcurrentScans`. Excess uploads still return 202 (the scan run is queued); a `queue_depth` Prometheus gauge tracks pressure.
- **OSV per-vuln-detail cache fix.** [`internal/scanner/manifest/osv/osv.go:316-321`](../../internal/scanner/manifest/osv/osv.go#L316-L321) currently reads `s.cache[vulnID]` but never returns the cached value and never writes fresh fetches. Fix:
  - Return the cached `Vulnerability` when present and unexpired.
  - Write fresh successful fetches into the cache under the existing `cacheMu`.
  - Preserve the existing TTL logic (the time field on the cache entry).
  - Add a unit test: two `hydrate` calls for the same CVE within the TTL window result in one HTTP fetch.
- **Why these belong here**: a `trivy image` SBOM produces ~10× more CVE hydration requests than `trivy fs`; without the cache, OSV's per-IP fair-use limits become reachable on a single image scan, and the gate's outbound network usage spikes proportionally. The semaphore is the second half of the same defense — it caps how many of those 10×-fan-outs run in parallel.

Checklist:
- [ ] `golang.org/x/sync/semaphore` wraps `go ScanService.Run(...)` at `scan_upload.go:86-88` and at `rescan.go:17`
- [ ] Default cap 4; `cfg.VulnScan.MaxConcurrentScans` Viper key
- [ ] Prometheus `vuln_scan_queue_depth` gauge wired
- [ ] OSV `hydrate` cache: read-and-return on hit, write-on-miss, mutex-guarded, TTL respected
- [ ] Unit test proves second hydrate call within TTL does not hit the network
- [ ] `docs/configuration.md` + `docs/features/vulnerability-scan.md` updated

### Phase 4 (separate PR): subprocess hardening

Deferred to its own PR `feature/shdg-subprocess-hardening`. Tracked separately because it touches both the existing `generateSBOM` and the new `generateImageSBOM` symmetrically, and because the security-review findings each require their own test surface. Scope:

- Stderr scrubber for `Authorization:` / `?token=` / `password=` patterns before embedding Trivy stderr in error messages (CLAUDE.md invariant 3).
- `cmd.Env` allowlist (`PATH`, `HOME`, `TMPDIR`, `XDG_CACHE_HOME`, `DOCKER_CONFIG`) — strip `TRIVY_*`, `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`.
- `exec.CommandContext` with timeout (default 15 min) so a hung registry pull cannot wedge CI indefinitely.
- `--` argv separator before user-controlled values (`exec.Command(trivy, "image", ..., "--", ref)`) — replaces the leading-dash syntactic guard.
- `io.LimitReader` cap on the tempfile read (100 MiB) — defense-in-depth against a runaway Trivy SBOM tempfile.

Applied uniformly to both subprocess invocations so the security posture of the new path matches the existing path.

## Risks and mitigations

| Risk | Impact | Probability | Mitigation |
|---|---|---|---|
| User runs `shdg scan --image <ref>` against a fresh Docker daemon without the image present and gets a confusing Trivy "not found" error. | Low (rc=1 with stderr from Trivy is interpretable) | Medium | Forward Trivy stderr verbatim into the wrapping error (`generateImageSBOM` mirrors the existing pattern at [`cmd/shdg/scan.go:187`](../../cmd/shdg/scan.go#L187)); document that `shdg` does not auto-pull. |
| `trivy image` for a large multi-arch image is slow (minutes); CI users perceive `shdg` as hanging. | Low — no SLA, but UX. | Medium | `--verbose` already prints the Trivy binary path; extend it to also print the `trivy image <ref>` command before exec, so users see what's running. No artificial timeout added — Trivy itself controls subprocess timeout via its own settings. |
| Private-registry pull fails silently if `docker login` was not run. | Medium — confusing failure mode in CI. | Medium | Document the `~/.docker/config.json` dependency in `docs/cli/shdg.md`. Trivy's own error message names the auth issue; we forward it via stderr. |
| Image reference contains a `:` and gets confused with a Trivy flag. | Low — Trivy is robust to OCI refs. | Very low | We pass `ref` as a separate `exec.Command` argument; no shell injection. Syntactic guard catches leading `-`. |
| User confuses build-context scan (no `--image`) with image scan (`--image`) and sees missing OS packages. | Medium — silent under-coverage if users keep the old form. | Medium | Update `docs/features/vulnerability-scan.md` and `docs/cli/shdg.md` to recommend `--image` for any Dockerfile project and explain the build-context-vs-image distinction in a callout. (No runtime stderr hint — rejected during review as too noisy for CI logs and hard to test without a clear AC.) |
| `trivy image` exits 0 but writes nothing (mirror of the `--format=cyclonedx` `--output -` quirk for `fs`). | Medium — false success. | Low | Mirror the existing empty-output guard at [`cmd/shdg/scan.go:193`](../../cmd/shdg/scan.go#L193) in `generateImageSBOM`. **Note:** distroless / `FROM scratch` images produce a *non-empty* CycloneDX with zero components — that is valid output, not an empty file. The guard fires only when Trivy writes zero bytes. |
| Concurrent `shdg scan --image` invocations in the same CI job race on the same tempfile. | Low. | Low | `os.CreateTemp("", "shdg-sbom-*.json")` (existing pattern) generates a unique path per call. |
| Multi-arch image manifest scanned on a different arch than production. | Low — silent shape divergence. | Medium | Document in `docs/cli/shdg.md`: "for production scans, pin a platform-specific digest (`myorg/api@sha256:...`) so the CI runner's host arch can't drift from the deployed arch." No flag added; Trivy's own platform selection is preserved. |
| Phase 2's 500 MiB SBOM cap × burst=10 implies 5 GiB worst-case server RSS. | Medium — gate OOM under pathological load. | Low | Phase 3's `max_concurrent_scans=4` semaphore caps how many of those uploads are actively scanning (the larger memory consumer). Document the new RSS budget in `docs/configuration.md`. Streaming SBOM ingestion is a tracked optimization for a later PR. |
| Phase 3 semaphore makes uploads return 202 but queue indefinitely if scans hang. | Medium — silent queue depth. | Medium | Add Prometheus gauge `vuln_scan_queue_depth` (semaphore current outstanding count) and dashboard alert at >2× cap sustained for 5 min. Existing `--wait` polling already times out on individual scans (rc=4), so callers see the failure. |
| OSV hydrate cache fix introduces a memory leak (unbounded cache growth). | Low — gate slow leak. | Low | Cache already has TTL plumbing (the `time.Time` field on entries) — fix correctly preserves it. Add a unit test for TTL expiry to lock the behaviour. |

## Testing

### Unit tests (`cmd/shdg/scan_test.go`)

- `TestRunScan_WithImageFlag_CallsTrivyImage_PostsToGate` — fake Trivy binary that writes a known CycloneDX file when invoked with `image <ref>`; assert upload reaches the gate with `ecosystem=docker`.
- `TestRunScan_ImageAndSbom_Returns2` — exclusivity guard (`--sbom` is user-supplied).
- `TestRunScan_ImageAndUserSuppliedDir_Returns2` — exclusivity guard when user explicitly passes `--dir`.
- `TestRunScan_ImageWithDefaultDir_DoesNotTripExclusivity` — regression guard: when only `--image` is supplied (no `--dir` on the command line), the default `.` value of `--dir` must **not** trigger the exclusivity check. This is the `fs.Visit` correctness test.
- `TestRunScan_ImageAndEcosystemPypi_Returns2` — `--image` + `--ecosystem pypi` rejected.
- `TestRunScan_ImageAndEcosystemDocker_Accepted` — `--image` + explicit `--ecosystem docker` is fine.
- `TestRunScan_ImageEmpty_Returns2` — empty `--image` rejected at parse time.
- `TestRunScan_ImageLeadingDash_Returns2` — `--image -malicious` rejected.
- `TestGenerateImageSBOM_EmptyOutput_ReturnsError` — fake Trivy that exits 0 without writing.

### Unit tests (`cmd/shdg/ecosystem_test.go`)

- `TestResolveEcosystem_ImageDefaultsToDocker` — `resolveEcosystem("", "/tmp", true)` returns `"docker"` even if `/tmp` has no markers.
- `TestResolveEcosystem_ImageExplicitOverride` — explicit `--ecosystem pypi` + `--image` returns `"pypi"` (label respected).

### Integration / E2E

E2E coverage lives in [`tests/e2e-shell/test_vuln_scan_shdg.sh`](../../tests/e2e-shell/test_vuln_scan_shdg.sh) (next to the existing `--sbom` sub-tests). Both sub-tests are gated on `command -v docker` and skip cleanly via `log_skip` when the runner lacks a Docker daemon — the existing E2E rig does not always ship one.

**Sub-test A — `shdg scan --image` happy path:**
- Pull `alpine:3.20` once (`docker pull alpine:3.20`).
- `shdg scan --image alpine:3.20 --project default --component "e2e-shdg-image-$(date +%s)" --wait --fail-on none --poll-interval 500ms --timeout 180s`.
- Assert rc=0 and a fresh scan run is visible via `GET /api/v1/vulnerabilities/scan-runs/{id}` with non-zero component count (OS packages present).

**Sub-test B — `shdg scan --image` + `--fail-on critical`:**
- Pull a known-vulnerable old tag (e.g. `alpine:3.10` — EOL, has accumulated CVEs).
- `shdg scan --image alpine:3.10 --project default --component "e2e-shdg-image-crit-$(date +%s)" --wait --fail-on critical --timeout 180s`.
- Expected rc=1 when the server reports criticals from **any** source (OS-layer or upstream-fix bias); accept rc=0 with `log_skip` when OSV is unreachable (mirroring the existing pypi-vulnerable sub-test's tolerance at [`tests/e2e-shell/test_vuln_scan_shdg.sh:97-108`](../../tests/e2e-shell/test_vuln_scan_shdg.sh#L97-L108)).
- This exercises the **full** `--image` path: subprocess invocation, SBOM size, server-side aggregation, and the `--fail-on` exit-code mapping — the survival of Sub-test B does not depend on which layer emits the critical, which keeps it stable across upstream Alpine fixes.

**Why two sub-tests:** Sub-test A proves the new invocation path works. Sub-test B proves the SBOM produced by `trivy image` flows through OSV/Trivy on the server and that criticals correctly surface in `--fail-on`. Without Sub-test B, a regression that silently produced an empty-but-valid SBOM could pass Sub-test A.

**Why a public image and not a fixture:** Unlike `--sbom`, the `--image` flow's whole point is to invoke Trivy against a real image. A pre-baked SBOM fixture would defeat the purpose. We pick `alpine:3.x` because it is small (~5 MB), well-known, and stable across years; the test rig pulls it once.

### Verification

Run between each phase, per CLAUDE.md "phased execution" rule:

```bash
make build                       # builds shdg + shieldoo-gate with new flag and bumps
make lint                        # `go vet` + golangci-lint clean
go test ./cmd/shdg/...           # Phase 1 unit tests pass
go test ./internal/component/... # Phase 2 SBOM cap test passes
go test ./internal/api/... ./internal/scanner/manifest/osv/...  # Phase 3 semaphore + OSV cache tests
make test                        # full unit suite green
bash tests/e2e-shell/run.sh test_vuln_scan_shdg   # E2E (Docker-gated sub-tests)

# Manual smoke (local):
SHIELDOO_TOKEN=$T SHIELDOO_URL=http://localhost:8080 \
  ./bin/shdg scan --image alpine:3.20 --project default --component smoke \
  --wait --fail-on none --timeout 120s
```

Grep for residual references that should have been updated:

```bash
grep -rn "trivy image" docs/ | grep -v "shdg.*--image"   # any remaining manual-curl examples?
grep -rn "manually run trivy image" docs/                # any stale wording?
grep -rn "10.*MiB\|MaxBytes.*10" internal/ docs/         # any stale 10-MiB cap references after Phase 2?
grep -rn "go func() { _ = s\.vulnDeps\.ScanService\.Run" internal/  # ensure all Run() invocations are semaphore-wrapped after Phase 3
```

## Notes

- **Backward compatibility.** Adding a flag is non-breaking. Existing `shdg scan --ecosystem docker --dir .` continues to work and continues to scan the build context — we do **not** silently flip behaviour. Users opt in via `--image`.
- **Stderr hint.** A one-line hint when `shdg` runs in `--ecosystem docker` without `--image` ("hint: scanning build context; use --image <ref> for full coverage") helps users discover the better path without breaking existing pipelines.
- **No new dependency on Docker daemon.** `shdg` itself does not import any Docker client — it just shells out to Trivy, which handles registry pulls and (when present) docker-daemon lookups on its own.
- **CLAUDE.md security invariant 4** (pinned scanner deps): respected — we use the same pinned Trivy v0.70.0 binary; no new pin, no new download, no version drift.
- **CLAUDE.md "no secrets in logs":** the `--image` reference itself is not a secret; Trivy may emit registry-auth diagnostics on stderr — we surface them verbatim, same as today's `generateSBOM`. We do not log `~/.docker/config.json` contents.
- **Idempotence.** Repeated `shdg scan --image alpine:3.20 --component web` creates multiple `scan_runs` rows under the same Component — identical semantics to the current `--dir`-based path.
- **`--fail-on critical` UX change.** Image scans surface OS-layer CVEs (deb/apk/rpm) that `trivy fs` never sees. Long-running production images on stable distros often carry "won't-fix" or "low-priority" CVEs that nevertheless get a critical CVSS score. Documented in `docs/cli/shdg.md`: "expect more findings than `trivy fs`; pin a baseline (or use per-component ignores) before enabling `--fail-on critical` in a blocking CI gate."
- **Component identity guidance.** A `Component` in Shieldoo Gate is a (project, name) tuple. Scanning the source tree and the built image of the same service into the same `Component` interleaves runs with very different shapes. Documented recommendation: use distinct names (`api-source` vs `api-image`) when both flows exist.
- **Trivy DB cache.** First `--image` run downloads ~30–50 MiB of vulnerability DB to `~/.cache/trivy`. CI cache-key authors should include that path. The bundled Trivy binary cache at `~/.cache/shdg/trivy-0.70.0/` is unchanged.
- **Follow-up PR — subprocess hardening.** A separate PR (`feature/shdg-subprocess-hardening`) tightens the `exec.Command` boundary for both `generateSBOM` and `generateImageSBOM`: stderr credential scrubber, `cmd.Env` allowlist, `exec.CommandContext` timeout, `--` argv separator, tempfile size cap. Tracked separately because each item carries its own test surface and applies symmetrically to the existing `trivy fs` path; bundling here would balloon the diff and obscure the `--image` feature.
- **Future enhancement (out of scope).** `--image-tarball` (offline registry-less scan via `trivy image --input image.tar`) is a small follow-up if CI users without a Docker daemon ask for it. Not in this analysis.

## References

- Existing vulnerability-scan feature design: [`docs/plans/2026-05-07-vulnerability-scan.md`](2026-05-07-vulnerability-scan.md) (or successor; this is the closest neighbour).
- Feature doc: [`docs/features/vulnerability-scan.md`](../features/vulnerability-scan.md).
- CLI doc: [`docs/cli/shdg.md`](../cli/shdg.md).
- Existing `trivy fs` invocation: [`cmd/shdg/scan.go:178-183`](../../cmd/shdg/scan.go#L178-L183).
- Server ingestion endpoint: [`internal/api/scan_upload.go:17`](../../internal/api/scan_upload.go#L17).
- Pinned Trivy version: [`cmd/shdg/trivy.go:22`](../../cmd/shdg/trivy.go#L22) (v0.70.0).
- Trivy `image` command reference: <https://aquasecurity.github.io/trivy/v0.70/docs/target/container_image/>.
- ADR-007 (vulnerability scan): [`docs/adr/ADR-007-vulnerability-scan.md`](../adr/ADR-007-vulnerability-scan.md).
