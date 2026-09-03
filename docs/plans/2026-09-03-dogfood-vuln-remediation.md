# Dogfood Vulnerability Remediation — 2026-09-03

Snapshot of the `shieldoo-gate` project's own vulnerability findings, taken from the
production gate (`ssh shieldoo-gate` → `shieldoo-gate-postgres-1`) on 2026-09-03,
plus the remediation plan derived from it.

**Data source:** `scan_findings` joined to `components.last_scan_id` for `projects.label = 'shieldoo-gate'`.
Production runs `0.19.9`; `main` is 15 commits ahead of the `v0.19.9` tag.

## 1. Snapshot

| Component | Ecosystem | Last scan | CRIT | HIGH | MED | LOW | INFO |
|---|---|---|---:|---:|---:|---:|---:|
| `scanner-bridge` | pypi | 2026-09-03 (rescan) | 0 | 0 | 0 | 0 | 0 |
| `gate` | go | 2026-09-03 (rescan) | 1 | 3 | 0 | 0 | 7 |
| `ui` | npm | 2026-09-03 (rescan) | 0 | 0 | 0 | 0 | 0 |
| `gate-image` | docker | 2026-09-03 (rescan) | 1 | 16 | 7 | 12 | 24 |
| `scanner-bridge-image` | docker | **2026-08-11 (STALE)** | 0 | 15 | 51 | 65 | 84 |

Rescans replay the *stored SBOM* against a fresh vuln DB. The SBOM itself is only
refreshed by the release pipeline (`release.yml` → `shdg scan`), so component
inventories reflect the last released build, not `main`.

### 1.1 `gate` (Go source tree, from `go.mod`)

| Sev | CVE | Package | In prod SBOM | Fixed in | Status on `main` |
|---|---|---|---|---|---|
| CRITICAL 9.1 | CVE-2026-56854 | `golang.org/x/crypto` (ssh auth bypass, source-address restrictions unenforced) | v0.54.0 | 0.55.0 | **fixed** — v0.56.0 (`046a60d`) |
| HIGH 8.8 | CVE-2026-56865 | `golang.org/x/mod` (sumdb tile verification bypass) | v0.38.0 | 0.40.0 | **fixed** — v0.40.0 |
| HIGH | CVE-2026-56864 | `golang.org/x/mod` (malicious GOSUMDB serves arbitrary module content) | v0.38.0 | 0.40.0 | **fixed** — v0.40.0 |
| HIGH | CVE-2026-84304 | `google.golang.org/grpc` (HTTP/2 DATA-frame OOM) | v1.83.0 | 1.83.1 | **fixed** — v1.83.2 (`505a5f5`) |

Plus 7 INFO rows from OSV covering the same three modules (x/crypto ssh DoS
GO-2026-6354/6355, unmaintained `openpgp` GO-2026-5932, x/mod GO-2026-6179/6180,
grpc GHSA-vp52-pcj8-j9qc).

**Every actionable `gate` finding is already fixed on `main` and merely unreleased.**

### 1.2 `gate-image` (container, alpine 3.24.1 + our binary + bundled trivy 0.74.0)

Three distinct origins:

**(a) Our Go binary** — 1 CRITICAL + 3 HIGH, identical to §1.1. Fixed on `main`.

**(b) Alpine base packages** — `libssl3` / `libcrypto3` at `3.5.7-r0`, fixed in `3.5.8-r0`:

| Sev | CVEs | Note |
|---|---|---|
| HIGH ×2 | CVE-2026-14456 | QUIC server unbounded memory growth (one row per package) |
| MED ×6 | CVE-2026-63072, CVE-2026-18798, CVE-2026-63076 | CMS heap overflow, QUIC INITIAL double-free, CMP null deref |
| LOW ×12 | CVE-2026-63074, CVE-2026-63075, CVE-2026-54874, CVE-2026-14457, CVE-2026-63073, CVE-2026-75803 | CMP/DTLS/QUIC memory + format-string issues |

`openssl 3.5.8-r0` **is already published in the alpine `v3.24` main repo**, but
`alpine:3.24.1` is still the newest published base tag, so a plain rebuild will
not pick it up — the runtime stage only runs `apk add`, never `apk upgrade`.

**(c) The bundled `aquasec/trivy:0.74.0` binary** — trivy 0.74.0 is the current
upstream release (published 2026-08-14), so these cannot be fixed by bumping trivy:

| Sev | CVE | Package | Fixed in |
|---|---|---|---|
| HIGH ×8 | CVE-2026-39821, -56858, -56853, -46600, -56860, -56859, -56862, -33818 | `stdlib` v1.26.5 | 1.26.6 / 1.27.0-rc.3 |
| HIGH | CVE-2026-71556 | `go-git/v5` v5.19.1 (symlink arbitrary file read/write) | 5.19.2 |
| MED | CVE-2026-71557 | `go-git/v5` v5.19.1 | 5.19.2 |
| HIGH | CVE-2026-50163 | `oras-go/v2` v2.6.1 (hardlink info disclosure) | 2.6.2 |
| HIGH | CVE-2026-84304 | `grpc` v1.82.1 | 1.83.1 |

Caveat on `stdlib`: the SBOM lists a **single** `stdlib v1.26.5` entry, because
`v0.19.9` was itself built with Go 1.26.5. After the next release (Go 1.27.1) the
stdlib rows should split — ours clean, trivy's still at 1.26.5. Verify this after
the release before suppressing anything.

### 1.3 `scanner-bridge-image` — data is 3 weeks stale, and permanently so

Last scan is `scan_runs.id = 1778` from **2026-08-11**. Every other component was
rescanned on 2026-09-03. Root cause found:

```
 id  | component_id | trigger | status  |          started_at
-----+--------------+---------+---------+------------------------------
 355 |            5 | rescan  | running | 2026-06-04 01:07:12.58959+00
```

`ManifestRescanScheduler.RunOnce` ([internal/scheduler/manifest_rescan.go:104-110](../../internal/scheduler/manifest_rescan.go#L104-L110))
selects components with `NOT EXISTS (… status IN ('pending','running'))`. Scan run
355 has been stuck in `running` for **three months** — presumably a process restart
mid-scan — and there is no reaper that ages such rows out. The component is
silently, permanently excluded from every rescan cycle, with **no log line**.

The 15 HIGH / 51 MEDIUM / 65 LOW rows on this component are all Debian trixie OS
packages (`ncurses` CVE-2025-69720, `gzip` CVE-2026-41992, `libacl1` CVE-2026-54369,
`util-linux`/`libblkid` CVE-2026-53615, …) with empty `fixed_version` *as of 2026-08-11*.
Their current state is unknown until a fresh scan runs.

### 1.4 Threat feed has never loaded on this deployment

535 consecutive failures since 2026-08-11 21:51 (hourly), initial refresh included:

```
threatfeed: fetching feed from https://feed.shieldoo.io/malicious-packages.json:
  tls: failed to verify certificate: x509: certificate is valid for
  *.msha-slice-4-am2-1-ase.p.azurewebsites.net, …, not feed.shieldoo.io
```

Confirmed directly — `feed.shieldoo.io:443` serves the Azure App Service Environment
default wildcard cert (`CN=*.msha-slice-4-am2-1-ase.p.azurewebsites.net`, issued
2026-07-21). The custom-domain TLS binding is missing on the feed's App Service.

Consequence: the `builtin-threat-feed` scanner has been evaluating every artifact
against an **empty feed** and returning `CLEAN` — visible in the logs as
`scanner=builtin-threat-feed verdict=CLEAN confidence=1`. This is a silent loss of
a detection layer, not a vulnerability finding, but it is the highest-impact item
in this snapshot.

## 2. Root causes

1. **Release lag** — all `gate` findings are fixed on `main`; nothing has shipped since v0.19.9 (2026-08-11).
2. **No `apk upgrade` in the runtime stage** — base-image OS CVEs can only be cleared by a new alpine tag, even when the fix is already in alpine's repo.
3. **No stale-run reaper** — a single `running` row wedged three months ago disables rescans for a component forever, silently.
4. **Suppression is version-blind** — `ApplySuppression` ([internal/component/store.go:476-490](../../internal/component/store.go#L476-L490)) matches on `(component_id, cve_id, package_name)` only; `cve_ignores.package_version` is stored but never used in the predicate. Suppressing a bundled-trivy `stdlib` CVE would also mask a future regression in *our* binary.
5. **Feed endpoint TLS misconfiguration** (infra, outside this repo).

## 3. Plan

Each phase is independently shippable. Phases 1–3 are separate PRs; phase 0 and 5 are ops actions.

### Phase 0 — Unwedge `scanner-bridge-image` (ops, immediate)

Mark the stuck run failed so the next rescan cycle picks the component up:

```sql
UPDATE scan_runs
   SET status = 'failed',
       finished_at = CURRENT_TIMESTAMP,
       error_message = 'reaped: stuck in running since 2026-06-04 (manual cleanup 2026-09-03)'
 WHERE id = 355 AND status = 'running';
```

`scan_runs` is not the audit log; UPDATE is permitted. Then trigger a rescan (or wait
for the daily cycle) and re-read the findings before deciding on any base-image action.

**Acceptance:** `components.id = 5` has a `scan_runs` row with `started_at > 2026-09-03`.

### Phase 1 — Cut release `v0.19.10` (ops)

Tag `main` and deploy. This alone clears 1 CRITICAL + 3 HIGH on `gate` and the same
4 on `gate-image`, plus the 8 `stdlib` HIGHs *for our binary* (Go 1.27.1).

Follow the release process: push tag `v0.19.10` → `release.yml` builds and pushes the
ghcr images → bump `SGW_VERSION` in prod `.env` → `docker compose pull && up -d`.

⚠️ **Release-gate risk:** `vuln-scan-image` runs `--fail-on critical` on `gate-image`.
If trivy 0.74.0 vendors its own `x/crypto` older than 0.55.0, bumping ours to 0.56.0
will surface CVE-2026-56854 as a *second* row and the release will fail. The prod SBOM
currently shows only one `x/crypto` entry, so this is unlikely but must be watched.
If it fires, land phase 3 first.

**Acceptance:** `gate` component shows 0 CRITICAL / 0 HIGH after the release scan.

### Phase 2 — `apk upgrade` in the runtime stage (PR)

[docker/Dockerfile:81](../../docker/Dockerfile#L81):

```dockerfile
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates sqlite-libs
```

This clears 2 HIGH + 6 MEDIUM + 12 LOW openssl findings on `gate-image` by pulling
`openssl 3.5.8-r0` from the pinned branch's live repo. The base image stays pinned by
digest, but `apk upgrade` deliberately widens the build-time surface to the entire
installed base set — a trade-off (security currency over byte-for-byte OS-layer
reproducibility) bounded by apk's package signature verification against the pinned
base's alpine keys, not a no-op. Document the rationale next to the pin comment and in
`docs/development/` alongside the existing base-image pinning notes (ADR-014).

Apply the same treatment to `scanner-bridge/Dockerfile` (`apt-get upgrade`) only after
phase 0 gives a current picture — with `fixed_version` empty on every Debian row as of
August, an upgrade may be a no-op.

**Acceptance:** `trivy image` on the rebuilt image reports `libssl3`/`libcrypto3` at `3.5.8-r0`.

### Phase 3 — Handle the bundled-trivy findings (PR + ops)

After phase 1, re-read `gate-image` findings and confirm the residual `stdlib`,
`go-git`, `oras-go`, `grpc 1.82.1` rows belong to `/usr/local/bin/trivy` and not to
our binary. Then, in order of preference:

1. **Wait for trivy 0.75.0** if it lands soon — it will be rebuilt against a patched Go and updated deps. Track upstream; this is the only fix that actually removes the risk.
2. **In the interim**, create `cve_ignores` rows for `gate-image` with a short `expires_at` (30 days) and a reason naming the bundled trivy version. Do *not* suppress `stdlib` CVEs unless phase 1 confirms our binary reports 1.27.1 separately — suppression is version-blind (root cause 4).
3. **Do not** blanket-skip `/usr/local/bin/trivy` from the image scan. Trivy parses untrusted artifact content inside the gate; its `go-git` symlink traversal and `oras-go` hardlink issues are on a real attack path, and hiding them removes the signal that would tell us when upstream ships a fix.

**Acceptance:** every remaining `gate-image` HIGH is either fixed or has an unexpired,
justified `cve_ignores` row.

### Phase 4 — Stale scan-run reaper (PR, prevents recurrence)

New scheduler in `internal/scheduler/` (mirrors the existing retention schedulers):
mark any `scan_runs` row `pending`/`running` with `started_at` older than a configurable
threshold (default: 4× `vuln_scan` scan timeout, floor 1h) as `failed` with
`error_message = 'reaped: stuck in <status>'`, and log at WARN.

Also add a WARN in `ManifestRescanScheduler.RunOnce` when an enabled component with a
`last_scan_id` is excluded by the in-flight predicate — the current silence is what let
this sit for three months.

Tests: `TestScanRunReaper_StuckRunning_MarkedFailed`,
`TestScanRunReaper_RecentRunning_Untouched`,
`TestManifestRescan_InFlightComponent_LogsSkip`.

Docs: `docs/` page for the vuln-scan schedulers + config reference for the new knob.

**Acceptance:** `make build && make lint && make test` green; new unit tests cover both branches.

### Phase 5 — Fix `feed.shieldoo.io` TLS (infra, outside this repo)

Rebind the custom domain + managed certificate on the feed's Azure App Service.

Separately, in this repo: the threat-feed client should not fail silently forever.
Add a metric/alert path so N consecutive refresh failures escalate beyond a WARN line —
an empty feed making every artifact look `CLEAN` is a fail-open the operator cannot see.
Worth an ADR if the fix changes `builtin-threat-feed`'s verdict semantics (e.g. reporting
`SCAN_UNAVAILABLE` instead of `CLEAN` when the feed has never loaded).

**Acceptance:** `curl -sSI https://feed.shieldoo.io/malicious-packages.json` returns 200
from prod; logs show a successful refresh.

## 4. Suggested order

| # | Phase | Type | Effort | Clears |
|---|---|---|---|---|
| 1 | 0 — unwedge run 355 | ops | minutes | unblocks visibility on 131 stale findings |
| 2 | 5 — feed TLS | infra | hours | restores a whole detection layer |
| 3 | 1 — release v0.19.10 | ops | ~1h | 2 CRIT + 6 HIGH + 8 stdlib HIGH |
| 4 | 2 — `apk upgrade` | PR | small | 2 HIGH + 6 MED + 12 LOW |
| 5 | 4 — reaper | PR | medium | prevents recurrence of phase 0 |
| 6 | 3 — trivy residuals | PR/ops | medium | remaining `gate-image` HIGHs |
