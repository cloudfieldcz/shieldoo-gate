# Design: Fail-Closed Scanner Error Handling

- **Date:** 2026-06-17
- **Status:** Proposed (v3 — revised after code review)
- **Scope:** Inline proxy scan gate — all serving/ingest paths in `internal/adapter/*`, plus `internal/policy`, `internal/scanner`.
- **Related ADR:** A follow-up `ADR-011-fail-closed-scanner-errors.md` should record the normative decision once this design is approved.

## Problem

When an inline scanner fails (crash, timeout, unreachable, overload), the proxy
serves the artifact unscanned. The security control that exists specifically to
block malicious artifacts silently disappears at the exact moment of failure. An
attacker who can degrade or overload the scanner bypasses all protection.

The fail-open pattern (`scanResults = nil` on `ScanAll` error) is replicated
across **nine** sites on serving/ingest paths:

| Path | Site | Client semantics |
|---|---|---|
| PyPI pull | `internal/adapter/pypi/pypi.go:337` | client GET, can retry |
| npm pull | `internal/adapter/npm/*.go` | client GET, can retry |
| NuGet pull | `internal/adapter/nuget/*.go` | client GET, can retry |
| Maven pull | `internal/adapter/maven/maven.go:537` | client GET, can retry |
| RubyGems pull | `internal/adapter/rubygems/rubygems.go:495` | client GET, can retry |
| Go modules pull | `internal/adapter/gomod/gomod.go:532` | client GET, can retry |
| Docker pull | `internal/adapter/docker/docker.go:996` | client GET, can retry |
| Docker push | `internal/adapter/docker/docker.go:472` | client PUSH (upload) |
| Docker sync | `internal/adapter/docker/sync.go:242` | background mirror, no client |

Downstream of every pull/push site:

- `internal/policy/aggregator.go:95,104-107` — `verdict` initialises to
  `VerdictClean`; errored results are silently skipped
  (`if r.Error != nil { continue }`). A nil/empty result set aggregates to `CLEAN`.
- `internal/policy/engine.go:340` — `CLEAN` → `ActionAllow`; adapters only return
  403 for `ActionBlock`/`ActionQuarantine`, otherwise serve.

Secondary fail-open (verdict normalisation):

- `internal/scanner/ai/scanner.go:183` — `UNKNOWN`/unexpected → `VerdictClean`.
- `internal/scanner/versiondiff/scanner.go:383` — `UNKNOWN` → fail-open.

This was historically documented as intentional (`CLAUDE.md`). We now treat it as
a design error to correct. The codebase is already internally inconsistent: the
**license** path is fail-closed (`internal/policy/engine.go:408` — "FAIL-CLOSED:
returns ActionBlock on DB/resolver errors").

## Goals

1. A required scanner that cannot produce a verdict MUST NOT result in an
   unscanned artifact being served (or pushed, or mirrored as clean).
2. Tolerate transient scanner blips without a hard outage (bounded retry +
   graceful degradation).
3. Keep noisy heuristic scanners from taking down the proxy (criticality tiers).
4. Make the failure behaviour an explicit, observable, operator-visible policy —
   not a silent default.

## Non-Goals (YAGNI)

- **Per-project override** of the failure mode. Forced global behaviour first.
- **Holding/staging the fetched artifact for background retry.** On the error
  path we discard it and let the client re-drive (see "Three failure
  semantics"). A non-servable staging area is deferred until a concrete need
  appears.
- Changing async/post-serve scanners (`internal/scanner/sandbox`, `Name()` =
  `sandbox`). They already quarantine-after-the-fact via the rescan scheduler.
- Changing the vuln-scan/SBOM service (`internal/component/scan_service.go`) — it
  is not on the serving critical path.

## Approach

Layered fail-closed. Five layers + two invariants. Three distinct failure
semantics depending on the path's client model.

### Three failure semantics

The "retry later" model only makes sense where a client re-drives the request.
The nine sites fall into three classes:

1. **Pull (6 ecosystems + docker pull):** client GET. On required-scanner
   failure → **HTTP 503 + `Retry-After`**, persist nothing, cache nothing. The
   client (pip/npm/docker/…) retries; the retry re-fetches upstream and
   re-scans. Stateless — no background job, no invented status, no cache-poison
   risk. Re-fetch cost on retry is accepted (only during scanner outage). The
   `Retry-After` value is `policy.retry_after` (default **30s**) with per-response
   jitter to spread retries — the 503 status is load-bearing; the header is an
   advisory hint that also dampens a retry storm against the already-stressed
   scanner (the overload threat model).
2. **Docker push:** client is uploading. There is no upstream to re-fetch. On
   required-scanner failure → **reject the upload (5xx)**; the artifact is never
   stored as servable. The pushing client may retry the push.
3. **Docker sync (background mirror):** no HTTP client waiting. On
   required-scanner failure → **skip the artifact; do NOT mark it clean/servable;
   leave it for the next sync cycle.** Never promote an unscanned mirrored
   artifact to a servable state.

`fail_open` (the escape hatch) preserves today's behaviour on all three classes.

### Configuration

Mirrors the existing `policy.on_sbom_error` enum (house style) and the existing
per-scanner `scanners:` config block. **Criticality is keyed by the scanner's
runtime `Name()` ID, not by the config-block alias.** Real IDs (every scanner
appended to the engine slice in `cmd/shieldoo-gate/main.go`, so all are
inline-gate scanners subject to criticality; unlisted ⇒ `best_effort`):
`builtin-threat-feed`, `hash-verifier`, `install-hook-analyzer`,
`obfuscation-detector`, `exfil-detector`, `pth-inspector`, `builtin-typosquat`,
`guarddog`, `ai-scanner`, `version-diff`, `builtin-reputation`, `trivy`, `osv`.
(`trivy`/`osv` are CVE/SBOM scanners; they run inline but should normally stay
`best_effort` — listed so an operator who *does* want one required knows the key.)

```yaml
policy:
  on_scan_error: "quarantine"   # quarantine(=503 / reject / skip) | block | fail_open ; default quarantine
  retry_after: "30s"            # pull-path 503 Retry-After hint; jittered per response
scanners:
  retry:
    max_attempts: 3
    backoff: "200ms"            # exponential backoff + jitter, hard-capped by scanners.timeout
  criticality:                  # keyed by scanner Name(); unlisted => best_effort
    builtin-threat-feed: "required"
    guarddog:            "required"
    ai-scanner:          "best_effort"
    version-diff:        "best_effort"
    builtin-reputation:  "best_effort"
```

**Startup validation (security control) — two gates, both run *post scanner
construction* in `cmd/shieldoo-gate/main.go` against the real engine slice.**
`cfg.Validate()` runs at `main.go:70`, *before* scanners are constructed
(`main.go:190+`), so neither gate can live there — `cfg.Validate()` keeps only
mode-enum + duration parsing. Validating against the actually-registered set
(not a hand-maintained name list) means there is nothing to drift.

1. **Unknown-key gate (typo guard):** every key under `scanners.criticality`
   MUST match a registered scanner `Name()`. An unknown key is fatal — otherwise
   a typo silently downgrades a `required` scanner to `best_effort`.
2. **Required-registered gate (init-failure guard):** every scanner marked
   `required` MUST be present in the constructed engine slice. Today optional
   scanners that fail init are logged and dropped
   (`main.go:206` — `guarddog scanner disabled: failed to init`); the same
   happens if a `required` scanner is simply not enabled. Either way it would
   never appear in `ScanReport.Expected`, so the runtime fail-closed check can
   never fire and every artifact serves clean — a *strictly worse* bypass than a
   runtime scan error, because there is no `Errored` signal at all (knock out the
   bridge socket → guarddog fails init on restart → silent disable). Therefore a
   `required` scanner that is missing or failed init is **fatal at startup**,
   UNLESS `on_scan_error: fail_open` (the explicit escape hatch). Net effect:
   `required` scanners become hard startup dependencies — fail fast instead of
   silently degrading.

### Layer 1 — Error taxonomy (`internal/scanner/errors.go`, new)

```go
type ScanErrorKind int
const (
    ErrKindNone ScanErrorKind = iota
    ErrKindRetryable   // timeout, conn refused, gRPC Unavailable/DeadlineExceeded
    ErrKindTerminal    // malformed artifact, unsupported type, gRPC InvalidArgument
    ErrKindOverload    // resource exhaustion, gRPC ResourceExhausted — the attack signal
)
type ScanError struct { Kind ScanErrorKind; Err error }
func (e *ScanError) Error() string   { ... }
func (e *ScanError) Unwrap() error   { return e.Err }
func (e *ScanError) Retryable() bool { return e.Kind == ErrKindRetryable || e.Kind == ErrKindOverload }
```

Scanners classify their own failures; a helper maps gRPC `status.Code` →
`ScanErrorKind`. Callers recover the kind via `errors.As`.

### Layer 2 — Retry + circuit breaker (scan-engine)

Wrap each `scanner.Scan` call:

- Bounded retry: `max_attempts`, exponential backoff + jitter, aborting on
  context deadline so total work stays within `scanners.timeout`. Only
  `Retryable()` errors retry; `ErrKindTerminal` does not.
- Per-scanner circuit breaker reusing the existing `policy.CircuitBreaker`
  pattern. **An open circuit yields a `ScanError` that flows into the
  completeness report — it never silently skips the scanner.**

### Layer 3 — Scanner engine reports completeness (`internal/scanner/engine.go`)

`ScanAll` currently returns `([]ScanResult, error)` and hides the applicable
scanner set, returning `nil, nil` when none apply — indistinguishable from
success. Replace with an explicit report:

```go
type ScanReport struct {
    Expected []string      // Name() of every scanner that should run (applicable, minus best_effort exclusions)
    Results  []ScanResult  // successful results (Verdict + Findings)
    Errored  map[string]*ScanError // scanner Name() -> failure after retries
    Skipped  []string      // best_effort scanners deliberately excluded (e.g. rescan drops ai-scanner)
}
```

This lets policy distinguish: no scanners applicable, a required scanner errored,
a best_effort scanner deliberately skipped, and a scanner that succeeded clean.

**Exclusion contract.** The current `ScanAll(…, excludeNames ...string)` is used
only by the rescan scheduler to drop `ai-scanner` (`rescan.go:230`), and it
removes excluded scanners *before* applicability is computed — so an excluded
scanner appears in neither `Results` nor `Expected`, i.e. it is invisible to any
completeness check. The replacement keeps the exclude parameter but constrains
it: **a `required` scanner can never be excluded** — an exclude request naming a
`required` scanner is ignored (it stays in `Expected` and runs), so no exclude
list can silently punch a hole in the required gate. Excluded `best_effort`
scanners are recorded in `Skipped` (and omitted from `Expected`) for
observability. This keeps the only real caller working — `ai-scanner` is
`best_effort`, so rescan still skips it — while making "exclude a required
scanner" structurally impossible rather than a per-caller discipline.

### Layer 4 — Policy applies `on_scan_error` (`internal/policy/engine.go`, `rules.go`)

New action:

```go
const ActionRetryLater Action = "retry_later"  // adapter maps to its path semantics
```

`Evaluate` gains the `ScanReport` and the criticality map. **Ordering w.r.t.
existing precedence (decided):**

1. DB override — `deny` → `ActionBlock`; `allow` → `ActionAllow`. (DENY still
   blocks even when the scanner is down.)
2. Static allowlist → `ActionAllow`.
3. **Incomplete check** — *after* override/allowlist, *before* verdict
   aggregation. An explicit allow-override or allowlist entry is a deliberate
   operator trust decision and **intentionally bypasses scanner-availability**;
   such an artifact is served even when a required scanner is down. This is
   documented behaviour, not an oversight.
4. License policy (unchanged).
5. If a `required` scanner is in `report.Errored` → apply `on_scan_error`:
   - `quarantine` → `ActionRetryLater`
   - `block` → `ActionBlock`
   - `fail_open` → treat as `CLEAN`, with loud log + metric + audit
6. Otherwise aggregate verdict as today. Best-effort-only failures proceed to
   normal mapping but emit audit/metric.

### Layer 5 — Adapters map `ActionRetryLater` to path semantics

- **Pull adapters** (pypi:337, npm, nuget, maven:537, rubygems:495, gomod:532,
  docker pull:996): replace `scanResults = nil; failing open` with passing the
  `ScanReport` into policy. `ActionRetryLater` → `503` + `Retry-After` + structured
  body. **Never `cache.Put`, never persist `artifact_status` on this path.**
- **Docker push** (docker.go:472): `ActionRetryLater` → reject upload with `5xx`;
  do not store the pushed artifact as servable.
- **Docker sync** (sync.go:242): `ActionRetryLater` → skip; do not write a
  clean/servable status; leave for next cycle. **Also fix the existing
  fall-through:** the current `default` branch (`sync.go:277-281`) persists
  `StatusClean` for *both* `ActionAllow` and `ActionBlock` ("block from sync just
  logs"). Under `on_scan_error: block` the required-errored artifact returns
  `ActionBlock` and would hit that default → persist clean → fail-open
  re-introduced. Sync MUST treat `ActionBlock` and `ActionRetryLater` as
  non-clean: skip (persist nothing servable), never `StatusClean`. This also
  closes the pre-existing latent `ActionBlock`→clean fall-through.

### Invariant A — No unscanned artifact becomes servable

Because the error path persists nothing and caches nothing, no servable
`artifact_status` row or cache entry is created from an incomplete scan. The
existing cache-hit fast paths (e.g. `pypi.go:278`) that block only `QUARANTINED`
remain correct **because there is no cache entry to hit.** No new status and no
`IsServable()` change are required. (If a future requirement forces *holding* the
fetched bytes to avoid re-fetch, it must introduce a non-servable status and
update both `IsServable()` and every cache-hit path — explicitly out of scope
now.)

### Invariant B — UNKNOWN from a required scanner is not clean

`internal/scanner/ai/scanner.go:183` and `internal/scanner/versiondiff/scanner.go:383`
emit `ScanError{Kind: ErrKindRetryable}` for `UNKNOWN` when the scanner is
`required`. From a `best_effort` scanner, `UNKNOWN` may remain advisory.

## Observability (= attack detection)

- Metrics: `scanner_errors_total{scanner,kind}`,
  `scan_error_mode_applied_total{mode,path}`, `circuit_breaker_state{scanner}`.
- New dedicated audit event **`EventScanUnavailable` = `"SCAN_UNAVAILABLE"`**
  (serving-path event, SCREAMING_SNAKE_CASE, sibling of `BLOCKED`/`QUARANTINED`).
  Emitted on **every** required-scanner-unavailable occurrence regardless of
  `on_scan_error` mode — so the `fail_open` bypass is never silent (mirrors the
  `super_token_used` invariant). `MetadataJSON` shape:
  `{"scanner":"builtin-threat-feed","kind":"overload","mode":"fail_open","path":"pull"}`
  where `mode` ∈ {`retry_later`,`block`,`fail_open`}, `path` ∈ {`pull`,`push`,`sync`}.
  Alert on `event_type=SCAN_UNAVAILABLE` (outage/attack signal); the
  `mode=fail_open` subset is the protection-bypassed signal — no reason-string
  parsing required. Follows the `LICENSE_CHECK_SKIPPED` / `SCANNER_VERDICT_DOWNGRADED`
  precedent (dedicated constant + structured metadata); does **not** reuse the
  async-vuln-scan `scan_run_failed` event. Registering a new event type touches
  four sites: `internal/model/audit.go`, `internal/config/config.go` (add to the
  `knownEventTypes` alert-filter allow-list, `config.go:192` — otherwise an
  operator alerting on `SCAN_UNAVAILABLE` trips the spurious "unknown event type"
  warning at `config.go:1144`; non-fatal but noisy), `ui/src/pages/AuditLog.tsx`
  (filter + colour map), `docs/api/openapi.yaml` (two `enum` lists).
- Prometheus alert on scanner error-rate / sustained `ResourceExhausted` —
  precisely the "someone is overloading the scanner to bypass the gate" signal.

## Data Flow (pull, required scanner down, default `quarantine`)

```
client GET → adapter.ScanAll
  → engine: retry(scanner.Scan) → ScanError after N attempts (or circuit open)
  → ScanReport{Expected:[...,builtin-threat-feed], Errored:{builtin-threat-feed: Retryable}}
  → policy.Evaluate: not overridden/allowlisted → required scanner errored
                     → on_scan_error=quarantine → ActionRetryLater
  → adapter: 503 + Retry-After ; NO cache.Put ; NO artifact_status write
  → metric scan_error_mode_applied_total{mode=quarantine,path=pull} + audit SCAN_UNAVAILABLE
client retries after Retry-After → scanner recovered → normal verdict → served or blocked
```

## Testing

- Unit: `ScanError` classification + gRPC mapping; retry honours `max_attempts`
  and context deadline; circuit open → `ScanError`; `ScanReport` distinguishes
  errored-required vs best-effort vs no-scanners.
- Config: unknown `scanners.criticality` key → fatal validation error.
- Policy: required-errored × `{quarantine, block, fail_open}` →
  `{ActionRetryLater, ActionBlock, ActionAllow}`; allow-override/allowlist on a
  required-errored artifact → `ActionAllow` (documented bypass); DENY-override →
  `ActionBlock`; best-effort-only failure → normal verdict mapping.
- Adapter integration (the core regression tests for the original vuln):
  - Pull: required-scanner error → `503` + `Retry-After`, no cache write, no
    serve; recovery on retry serves/blocks.
  - Push: required-scanner error → `5xx`, artifact not stored servable.
  - Sync: required-scanner error → artifact skipped, status not clean.
- Test naming per `CLAUDE.md`, e.g. `TestPyPIAdapter_RequiredScannerError_Returns503`,
  `TestDockerPush_RequiredScannerError_Rejects`, `TestConfig_UnknownCriticalityKey_Fatal`.

## Files Touched (estimate)

| Area | Files |
|---|---|
| Error taxonomy | `internal/scanner/errors.go` (new), `internal/scanner/interface.go` |
| Retry/breaker + report | `internal/scanner/engine.go`, reuse `internal/policy/circuitbreaker` |
| Aggregator | `internal/policy/aggregator.go` |
| Policy | `internal/policy/engine.go`, `internal/policy/rules.go` |
| Pull adapters | `internal/adapter/{pypi,npm,nuget,maven,rubygems,gomod}/*.go`, `internal/adapter/docker/docker.go` (pull) |
| Push/sync | `internal/adapter/docker/docker.go` (push), `internal/adapter/docker/sync.go` |
| Scanner normalisation | `internal/scanner/ai/scanner.go`, `internal/scanner/versiondiff/scanner.go` |
| Config + validation | `internal/config/config.go` (mode/duration parse), `cmd/shieldoo-gate/main.go` (two post-construction startup gates), `config.example.yaml` |
| Audit event | `internal/model/audit.go` (`EventScanUnavailable`), `internal/config/config.go` (`knownEventTypes` + config test), `ui/src/pages/AuditLog.tsx` (filter + colour), `docs/api/openapi.yaml` (two event-type enums) |
| Docs | `docs/policy.md`, `docs/scanners.md`, `docs/adr/ADR-011-*.md`, `CLAUDE.md` (update fail-open invariant) |

Phased per `CLAUDE.md` (~5 files/phase, build+test between phases). Suggested
order: taxonomy → engine retry/breaker + `ScanReport` → aggregator → policy →
pull adapters → push/sync → normalisation → config/validation/docs.

## Resolved Review Findings

- **F1** (incomplete adapter scope) — all 9 sites enumerated; pull/push/sync split.
- **F2** (rescan path not implementable) — dropped background rescan; stateless
  503 re-driven by client. No `TriggerAsyncScan`, no scheduler dependency.
- **F3** (`StatusPendingRescan` missing / pending servable) — error path persists
  nothing; no new status; Invariant A reworded.
- **F4** (override precedence) — explicit: allow-override/allowlist bypasses the
  incomplete check; DENY still blocks; incomplete check sits after allowlist,
  before verdict aggregation.
- **F5** (expected scanners) — concrete `ScanReport{Expected, Results, Errored}`.
- **F6** (config keys vs scanner IDs) — criticality keyed by real `Name()` IDs +
  fatal startup validation against the registry.

### Round 2 (document/code consistency review)

- **F7** (required scanner init-failure escapes `Expected`) — added the
  **required-registered startup gate**: a `required` scanner that is missing or
  failed init is fatal unless `on_scan_error: fail_open`. Closes the no-`Errored`
  bypass (knock out the bridge → silent disable → serve clean).
- **F8** (docker sync maps `ActionBlock`→`StatusClean`) — Layer 5 sync now treats
  both `ActionBlock` and `ActionRetryLater` as non-clean (skip), and explicitly
  fixes the pre-existing `default`-branch fall-through at `sync.go:277-281`.
- **F9** (config-validation location not viable — `cfg.Validate()` precedes
  scanner construction) — both name gates moved to *post-construction* in
  `main.go` against the real engine slice; `cfg.Validate()` keeps only
  mode/duration parsing. Collapses F1/F6/F9 validation into one drift-free site.
- **F10** (IDs list omits `trivy`/`osv`) — both added; noted as inline scanners
  defaulting to `best_effort`.
- **F11** (count: "eight" vs nine table rows) — corrected to **nine**.

### Round 3 (document/code consistency review)

- **F12** (Medium — `ScanReport` cannot represent excluded scanners; `ScanAll`'s
  `excludeNames` drops them before applicability, `engine.go:46`/`rescan.go:230`)
  — added `Skipped []string` to the report **and** an exclusion contract: a
  `required` scanner can never be excluded (the exclude is ignored and it stays in
  `Expected`). Closes the "exclude a required scanner" silent-bypass class by
  construction.
- **F13** (Low — event-registration site list incomplete) — `SCAN_UNAVAILABLE`
  must also be added to `config.go`'s `knownEventTypes` allow-list (`config.go:192`)
  or it trips the non-fatal "unknown event type" warning (`config.go:1144`);
  registration corrected from three to **four** sites + a config test.
- **F14** (Low — stale in-doc numbers) — "eight sites" → nine (failure-semantics
  intro), "all 8 sites" → nine (F1 ledger), data-flow `scan_unavailable` →
  `SCAN_UNAVAILABLE`.

## Open Questions

None — all review findings and design decisions resolved. Ready for an
implementation plan.
