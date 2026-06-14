# Scanner scratch temp cleanup — periodic janitor (issue #24)

## Overview

Trivy and GuardDog create internal scratch during scans (analyzer dirs, blob
cache, decompression buffers). That scratch is not reliably removed on scanner
timeout, crash, or a hard kill of the host process (SIGKILL/OOM). Because the
scratch lives on `/tmp`, which is a **shared, named (persistent) Docker volume**
(`bridge-socket`) mounted into both the gate and the scanner-bridge containers,
the ephemeral data becomes permanent and grows without bound — observed at
33 GB+ on production, threatening disk-full outages.

This plan removes the leak by adding a **periodic age-based janitor** in both
processes (gate and bridge) that deletes the stale, process-owned scratch it can
prove is disposable — Trivy scratch, GuardDog temp, the manifest SBOM temp, and
orphaned adapter staging *files* — while keeping the existing volume topology
untouched. Scratch is given a controlled, process-owned location so the janitor
can delete it safely without touching the socket, the Docker push blob store, or
an in-flight download/scan.

> **Supersedes PR #26.** That PR attempted the same goal but (a) moved the
> `bridge-socket` volume off `/tmp`, which silently broke artifact passing
> between gate and bridge (fail-open CLEAN — see Constraint 1), and (b) isolated
> GuardDog temp by mutating the process-global `tempfile.tempdir` per scan, which
> races under the 64-thread gRPC pool (fail-open cascade — see Constraint 2). PR
> #26 is closed; this plan is the clean replacement.

### Why

- **Fixes the real root cause.** The leak is *missing cleanup*, not *where the
  data lives*. A janitor that sweeps stale scratch addresses it directly without
  changing the deployment topology.
- **Safe by construction.** Age-based deletion (mtime older than a threshold far
  above the scan timeout) can never remove an in-flight scan's scratch — no scan
  activity tracking, no locks, no races.
- **Defence in depth.** The janitor is the backstop for the one case a per-scan
  `defer`/`finally` cleanup cannot cover: a hard kill of the whole process
  mid-scan.

## Hard constraints (must not violate)

1. **`/tmp` must stay shared between gate and bridge.** The gate stages each
   download via `os.CreateTemp("", "shieldoo-gate-<eco>-*")` →
   [`internal/adapter/pypi/pypi.go:603`](../../internal/adapter/pypi/pypi.go#L603)
   (and the equivalent in every adapter) and sends that path
   (`scanArtifact.LocalPath`, [`pypi.go:328`](../../internal/adapter/pypi/pypi.go#L328))
   to the bridge, which opens it via `scan_local()`
   ([`scanner-bridge/main.py`](../../scanner-bridge/main.py), `ScanArtifact`).
   The gate sets **no** `TMPDIR`, so this path is `/tmp`. It only works because
   `bridge-socket` is mounted at `/tmp` in both containers. Unmounting `/tmp`
   (as PR #26 did) → bridge gets `FileNotFoundError` → GuardDog/AI scan
   fail-opens to `CLEAN`. **Do not move the `bridge-socket` mount off `/tmp`.**
2. **No per-scan mutation of process-global temp state.** The bridge serves on
   `ThreadPoolExecutor(max_workers=64)`; mutating `tempfile.tempdir` per
   `ScanArtifact` call races across concurrent scans and leaves the global
   pointing at a deleted dir → subsequent `mkdtemp` raises → fail-open cascade.
   Any temp redirection must be done **once at startup**, before scan threads run.
3. **Version pinning.** Do not regenerate proto stubs with a non-pinned protobuf
   (`scanner-bridge/requirements.txt` pins `protobuf==5.29.6`). Generated
   `scanner_pb2*.py` are rebuilt at Docker build time, so leave checked-in stubs
   as-is unless regenerating with the pinned version via `make proto`.
4. **Cleanup must be scoped and TOCTOU-safe.** The janitor must never delete the
   gRPC socket, another tool's temp, or an in-flight download/scan. It deletes
   only entries it owns and only when older than the safety threshold.
   Because `/tmp` holds attacker-influenced content (decompressed package
   payloads can carry arbitrary file/dir names, symlinks, and mtimes), the sweep
   MUST:
   - enumerate only **direct children** of the target dir via `os.ReadDir` /
     `os.scandir` — never a recursive glob;
   - decide age from the **top-level entry's** `Lstat` mtime only (never recurse
     for the age decision — a nested attacker-set mtime must not keep scratch
     alive or bias deletion);
   - **skip symlinks** entirely (never follow or delete them);
   - reject any entry whose name contains `/` or `..`;
   - keep an explicit denylist so neither the gRPC socket (`BRIDGE_SOCKET`) nor
     the Docker push blob store directory (`shieldoo-gate-blobs`) is ever removed,
     even if a same-prefix decoy is planted next to them;
   - for the `shieldoo-gate-` staging prefix, delete only **regular files** (the
     adapters' staging temps are always files via `os.CreateTemp`); never delete
     a directory under that prefix. This is the structural guard that keeps the
     blob store (a directory) out of scope on top of the explicit denylist.

## Current state

- `/tmp` is the shared `bridge-socket` volume in
  [`docker/docker-compose.yml`](../../docker/docker-compose.yml) (gate +
  bridge), [`tests/e2e-shell/docker-compose.e2e.yml`](../../tests/e2e-shell/docker-compose.e2e.yml),
  and [`examples/deploy/compose.yaml`](../../examples/deploy/compose.yaml).
- `BRIDGE_SOCKET` defaults to `/tmp/shieldoo-bridge.sock`
  ([`scanner-bridge/main.py`](../../scanner-bridge/main.py) `serve()`).
- Trivy subprocesses are launched in
  [`internal/scanner/trivy/trivy.go`](../../internal/scanner/trivy/trivy.go)
  (`scanCycloneDX`, `scanLegacy`) and
  [`internal/scanner/manifest/trivy/trivy.go`](../../internal/scanner/manifest/trivy/trivy.go);
  none set a per-invocation `TMPDIR`, so Trivy scratch lands directly in `/tmp`
  with Trivy-chosen names.
- GuardDog runs in-process in the bridge (`scan_local`); its temp lands in
  `tempfile.gettempdir()` = `/tmp`.
- Adapters stage each download as a top-level **file** `shieldoo-gate-<eco>-*`
  via `os.CreateTemp`. The happy path removes it with `defer os.Remove`
  ([`pypi.go:309`](../../internal/adapter/pypi/pypi.go#L309)); it orphans only on
  a hard kill. Its lifetime is bounded by `PipelineTimeout = 5m`
  ([`internal/adapter/base.go:278`](../../internal/adapter/base.go#L278)),
  including the async sandbox path that reads it after the HTTP response.
- The manifest Trivy scanner also writes a `shieldoo-sbom-*.json` temp file to
  `/tmp` ([`internal/scanner/manifest/trivy/trivy.go:93`](../../internal/scanner/manifest/trivy/trivy.go#L93),
  `defer os.Remove`); it orphans only on hard kill — same leak class, different
  prefix, so the janitor must cover it explicitly.
- The Docker push **blob store** moved to the durable `cache.BlobStore`
  (`docker-push/` namespace) per **ADR-009** — it is **no longer written under
  `/tmp`**, and startup now enforces that the `local` backend path is not under
  `/tmp` when push is enabled. The only `os.TempDir()/shieldoo-gate-blobs`
  directory that can still exist is a **legacy, pre-migration** store
  ([`cmd/shieldoo-gate/main.go:158`](../../cmd/shieldoo-gate/main.go#L158)); until
  the operator runs `-migrate-push-blobs` it remains the *sole* copy of those
  pushed images, and main.go explicitly warns to migrate it
  ([`main.go:178`](../../cmd/shieldoo-gate/main.go#L178)). Deleting it loses a
  pushed image and, via fall-through-to-upstream on a miss, risks serving
  unscanned content — so the janitor **must not** touch `shieldoo-gate-blobs`
  (denylist + files-only guard, since it is a directory). The migration's own
  cleanup reclaims it after a content-verified move; the janitor never races that
  because it never enumerates into the excluded directory. Its lifecycle is out
  of scope (see below).
- Nothing sweeps any of these. There is precedent for cleanup workers:
  [`docs/scanners.md`](../../docs/scanners.md) "Orphan Cleanup" (sandbox) and the
  retention schedulers wired in
  [`cmd/shieldoo-gate/main.go`](../../cmd/shieldoo-gate/main.go) (background
  `Start(ctx)` services).

## Proposed design

### Naming so the janitor can delete safely

`/tmp` is shared and also holds the socket. The janitor must therefore target
only entries it can prove are Shieldoo-owned, all sharing a `shieldoo-` prefix:

- **Go / Trivy:** Trivy currently writes scratch under Trivy-chosen names that no
  prefix would match, so this is **net-new work**: give each Trivy subprocess its
  own scratch dir via `cmd.Env` (`TMPDIR=<per-scan dir>`), named
  `shieldoo-trivy-scratch-*`. This is **thread-safe** (env is per-subprocess, not
  a process global) and namespaces *all* Trivy scratch under a known prefix. Apply
  this in **both** [`internal/scanner/trivy/trivy.go`](../../internal/scanner/trivy/trivy.go)
  and [`internal/scanner/manifest/trivy/trivy.go`](../../internal/scanner/manifest/trivy/trivy.go).
  A per-scan `defer os.RemoveAll` gives deterministic cleanup on the happy path;
  the janitor covers hard kills. (Existing extraction dirs already named
  `shieldoo-trivy-*` in `trivy.go` will also be matched — beneficial, it backstops
  their hard-kill leak too.) **Set the env additively** —
  `cmd.Env = append(os.Environ(), "TMPDIR="+dir)` — never a bare
  `cmd.Env = []string{...}`, or Trivy loses `PATH`/`HOME`/proxy/DB-download config
  and every scan fail-opens. Also redirect the `shieldoo-sbom-*.json` temp in the
  manifest scanner into the same per-scan dir (or rename it `shieldoo-trivy-sbom-*`)
  so it is removed with the scratch and matched by the `shieldoo-trivy-` prefix.
- **Python / GuardDog:** at bridge startup (before serving), create a dedicated
  `<tmp>/shieldoo-guarddog/` and point `tempfile.tempdir` + `TMPDIR` there once.
  Thread-safe (never mutated per scan). The directory is owned exclusively by the
  bridge, so the janitor may delete any stale entry in it regardless of
  GuardDog's internal naming.
- **Adapter staging files only:** the adapters' staging temps are top-level
  *files* `shieldoo-gate-<eco>-*` created by `os.CreateTemp` (e.g.
  `shieldoo-gate-docker-*.tar`, `shieldoo-gate-pypi-*`). The janitor sweeps these
  by the `shieldoo-gate-` prefix **restricted to regular files** (Constraint 4) —
  short-lived (5m `PipelineTimeout`, ≪ maxAge), so deletion never races the async
  sandbox path. The `shieldoo-gate-blobs` **directory** under the same prefix is
  the push blob store and is explicitly excluded (denylist + files-only guard).

### Janitor

- New package `internal/scanner/tmpjanitor` (Go): `Janitor` with
  `Run(ctx)` (initial sweep + `time.Ticker` loop, stops on `ctx.Done()`) and a
  `Sweep(now) int` (deterministic given a clock; it does filesystem I/O, so not
  pure — tested against `t.TempDir()`) that removes entries matching configured
  prefixes in a target dir whose top-level `Lstat` mtime is older than `maxAge`,
  following the TOCTOU-safe rules in Constraint 4. Started from
  [`cmd/shieldoo-gate/main.go`](../../cmd/shieldoo-gate/main.go) under the
  graceful-shutdown `ctx` when Trivy is enabled. Sweeps `os.TempDir()` (the same
  resolver the adapters use — keeps janitor target and leak location in lockstep)
  for: `shieldoo-trivy-*` (dirs — Trivy scratch + the redirected SBOM temp),
  `shieldoo-sbom-*` (files, only if not redirected per Naming), and
  `shieldoo-gate-*` **regular files only** (adapter staging), excluding the
  `shieldoo-gate-blobs` directory (see Constraint 4 + Naming). The bridge sweeps
  `shieldoo-guarddog/`. The sandbox's own `sgw-sandbox-*` temp is **not** a
  `shieldoo-` prefix and is left to its existing `CleanupOrphans` worker — no
  overlap. The Go and bridge prefix sets are disjoint, so the two janitors never
  double-stat or race a delete on the shared volume.
- Bridge (Python): a `daemon` thread running `_run_scratch_janitor(scratch_dir,
  interval, max_age, stop_event)` — initial sweep + `stop_event.wait(interval)`
  loop. `_sweep_scratch` lists `scratch_dir` with `os.scandir` and removes
  entries older than `max_age`. Started in `serve()` after `setup_scratch_dir()`.
- **Per-sweep deletion cap (both sides):** delete at most `N = 100` entries per
  cycle. The first post-deploy sweep faces the existing backlog (33 GB+); an
  uncapped `os.RemoveAll` over thousands of inodes is one blocking metadata storm
  that contends with in-flight scans and can push a borderline scan past its
  timeout (→ fail-open CLEAN). Capping drains the backlog over several cycles
  instead: drain rate is `N` per `interval` = 600 stale entries/hour at the
  defaults, which must exceed the peak scratch-production rate (≤1 top-level entry
  per completed/killed scan) — trivially true, and only stale (`> maxAge`) entries
  count, so fresh scratch never blocks the drain. **Ordering is unspecified** —
  every eligible entry is already past `maxAge` and equally safe, so a strict
  oldest-first sort (which would force an `Lstat` + sort over the whole listing) is
  not required; a single capped pass suffices. Each sweep continues on per-entry
  error (EPERM / cross-UID / busy dir → skip + log + count, never abort the whole
  sweep).
- **Observability:** every sweep logs entries + bytes reclaimed and entries
  skipped. The Go side additionally registers **net-new** Prometheus metrics
  (reclaimed-bytes / reclaimed-entries counters, last-sweep-timestamp gauge) using
  the existing `promauto`/registry pattern in
  [`internal/api/metrics.go`](../../internal/api/metrics.go) — define them inside
  `tmpjanitor` and register via the shared registry to avoid a `tmpjanitor →
  internal/api` import cycle (do not assume a reusable cleanup-metric precedent;
  there is none). The bridge janitor is **log-only by design** (the Python sidecar
  exposes no Prometheus endpoint); operators monitor the gate metrics + bridge
  logs. The last-sweep gauge going stale is the thread-death signal — log-grepping
  is not an operability strategy for a recurring disk-full incident.
- **Defaults (hardcoded):**
  - interval = 10 min.
  - **Go maxAge** = `max(1h, 5 × scanners.timeout)` (`scanners.timeout` default
    `60s` → floor 1h dominates; the 5× term only governs when an operator raises
    the scan timeout above ~12 min). The large maxAge guarantees an in-flight
    scan's scratch is always "too fresh" to delete.
  - **Bridge maxAge** = fixed **1h floor**. The bridge sets no server-side guard
    on the GuardDog `scan_local` path; the *effective* bound is the gate's gRPC
    deadline, which propagates the engine's `scanners.timeout` (default 60s,
    [`internal/scanner/engine.go:69`](../../internal/scanner/engine.go#L69)). The
    bridge does not know that value, so it cannot derive a 5× margin and uses a
    fixed 1h (~60× the default). **Note for operators:** raising `scanners.timeout`
    toward 1h would require raising this bridge floor — document it.

### Phases

| Phase | Scope (≤1 module) | Verify |
|---|---|---|
| 1 | `internal/scanner/tmpjanitor` package + unit tests (incl. TOCTOU/symlink: socket survives a same-prefix decoy, symlink-to-socket/cache skipped, `..`-named entry rejected, per-entry delete failure does not abort sweep, per-sweep cap deletes oldest-first) | `go test ./internal/scanner/tmpjanitor/...` |
| 2 | **Add** per-scan `TMPDIR=shieldoo-trivy-scratch-*` + `defer os.RemoveAll` to **both** `internal/scanner/trivy/trivy.go` and `internal/scanner/manifest/trivy/trivy.go`; wire janitor (+ metrics) into `main.go` | `make build && make test` |
| 3 | Bridge: `setup_scratch_dir()` once at startup + daemon janitor (1h maxAge floor, per-sweep cap, log reclaimed/skipped); **no** per-scan global mutation | `pytest scanner-bridge/tests/` |
| 4 | Docs: `docs/scanners.md` temp/janitor section + link new behavior from `docs/index.md`; leave `docs/scanners/version-diff.md` (correctly describes shared `/tmp`) | docs review |
| 5 | Sweep + blob-store-survival coverage — see **E2E deviation** below: a production-wiring Go test (`go test ./internal/scanner/tmpjanitor/...`) asserts a stale `shieldoo-trivy-*` dir is reclaimed while a **live unix socket**, a fresh in-flight staging file, and the legacy `shieldoo-gate-blobs` dir survive; pypi/npm scan-still-works is covered by the existing `test_vuln_scan_pypi`/`test_vuln_scan_npm` suites | `go test ./internal/scanner/tmpjanitor/...` + `make test-e2e-containerized` |

### E2E deviation (recorded during implementation)

The original Phase 5 planned a containerized e2e that plants a stale
`shieldoo-trivy-*` dir, triggers a sweep, and ages the `/tmp` push blob store.
Two facts make that infeasible / obsolete as written:

1. **Harness limits (same as the durable-push e2e deviation).** The test-runner
   container mounts only the logs volume — **not** the `bridge-socket` (`/tmp`)
   volume — and cannot exec into or restart the gate. So it can neither plant a
   file in the gate's `/tmp` nor trigger an on-demand sweep (10-min ticker, no
   trigger endpoint, 1h `maxAge`). Making interval/maxAge configurable for the
   test is the out-of-scope tuning this plan explicitly deferred.
2. **ADR-009 moved push blobs out of `/tmp`.** Active push blobs now live in the
   durable `cache.BlobStore` (`docker-push/`); the only `/tmp/shieldoo-gate-blobs`
   is a *legacy, pre-migration* dir. "Age the blob store, sweep, pull" no longer
   maps to the durable store, and the durable-push serve path is already covered
   by `test_docker_push_durable.sh`.

**Resolution:** the sweep itself and the blob-store/socket exclusions are proven
by the `tmpjanitor` Go tests, including a production-wiring test that constructs
the janitor exactly as `main.go` does (real unix socket, `DefaultRules`, the
production denylist). The TMPDIR change is exercised end-to-end by the existing
vuln-scan e2e suites (a broken Trivy env would fail-open and fail those
assertions). This mirrors the precedent set when durable push storage hit the
same harness limitation.

## Risks

- **Janitor deleting an in-flight scan.** Mitigated by the age threshold ≫ scan
  timeout; an active scan's scratch is always fresh. Staging files (5m
  `PipelineTimeout`) sit ≫ below the 1h floor, so the async sandbox path is safe
  too. Relies on the top-level entry's mtime reflecting scan liveness — true for
  `MkdirTemp`-created dirs killed at 1× timeout (Go) and ≪ 1h GuardDog scans.
- **maxAge too low for very long scans.** Go side scales with `scanners.timeout`
  (`5×`); bridge uses a fixed 1h floor since it has no scan timeout to scale from.
- **Sweep I/O contends with in-flight scans.** The sweep `stat`/`unlink` traffic
  runs against the same volume Trivy/GuardDog are writing to. Mitigated by the
  per-sweep deletion cap (oldest-first) so no single cycle — including the first
  backlog-draining sweep — issues a stop-the-world `RemoveAll` that could starve a
  scan into timeout.
- **Shared `/tmp` still accumulates if the janitor thread dies.** Daemon thread +
  goroutine are simple and emit metrics + logs on every sweep; failure is visible
  via the last-sweep-timestamp gauge going stale. Acceptable.

## Out of scope

- Moving the socket to `/var/run/shieldoo` (rejected — see Constraint 1).
- A lifecycle/eviction policy for the Docker push blob store. Active push blobs
  now live in the durable `cache.BlobStore` (`docker-push/`, ADR-009), whose GC
  is a separate retention follow-up (delete on tag-delete / quarantine purge —
  ADR-009 Consequences). The legacy `os.TempDir()/shieldoo-gate-blobs` directory
  is **explicitly excluded** from this janitor (denylist + files-only guard) so
  it survives until the operator runs `-migrate-push-blobs`; deleting it would
  lose images / risk serving unscanned upstream content. Neither is solvable by
  an age-based `/tmp` sweep.
- Making interval/maxAge operator-configurable (`scanners.tmp_janitor.*`).
  Reasonable per project convention, but the hardcoded defaults solve the
  incident; defer to a follow-up if operators need to tune it.
- Resyncing the checked-in `scanner_pb2.py` with `scanner.proto` (a pre-existing
  desync unrelated to this leak — track separately; regenerate with pinned
  protobuf 5.29.6 via `make proto`).
