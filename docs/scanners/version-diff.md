# Version-Diff Scanner

> **Status:** v2.0 (AI-driven) — replaces the v1.x static heuristic implementation.
> See [ADR-005](../adr/ADR-005-ai-driven-version-diff.md) for the rebuild rationale.

The `version-diff` scanner detects malicious supply-chain attacks by comparing
each new package version against its most recent CLEAN/SUSPICIOUS cached
predecessor. Both versions are sent to the Python `scanner-bridge` over gRPC,
where extraction and an LLM call (gpt-5.4-mini default) classify the changes
as `CLEAN`, `SUSPICIOUS`, or `MALICIOUS`. The Go side maps the verdict to a
`scanner.Verdict`, persists the result, and applies a deliberate
`MALICIOUS → SUSPICIOUS` downgrade (see "Verdict mapping" below).

## When does it run?

- Per-artifact, in parallel with all other enabled scanners.
- Skipped (returns CLEAN, no error — genuinely "nothing to scan") when:
  - The package name is in the configured `allowlist`.
  - No previous CLEAN/SUSPICIOUS version exists in the artifacts table. This
    includes a **first-seen package that exceeds `max_artifact_size_mb`** —
    with no predecessor there is no diff to perform, so the size guard does not
    apply and the scan is a genuine no-op (not a fail-closed condition).
  - An idempotent cache hit is found in `version_diff_results` for the
    `(new artifact, previous artifact, model, prompt version)` tuple.
- "Couldn't scan" (returns CLEAN **with a classified scanner error**) when:
  - The per-package rate limiter has exhausted the hourly quota — `throttled`.
    This is intentional local backpressure on one package, **not** a backend
    health signal, so (like `terminal`) it is excluded from the scanner-wide
    health circuit breaker — otherwise a single hot package hammering its quota
    would open the breaker and fail unrelated, healthy packages as overload.
  - The consecutive-failure circuit breaker is open — `throttled`. This is
    version-diff's OWN local self-protection breaker (backend protection after
    repeated bridge errors). version-diff is an **enrichment-class** scanner and
    has no engine per-scanner breaker at all ([ADR-013](../adr/ADR-013-enrichment-scanner-breaker-exemption.md));
    this internal breaker is its sole backend-health guard.
  - The previous-version DB lookup itself fails (lock, timeout, schema) —
    `retryable`. Only `sql.ErrNoRows` means "no previous version"; any other
    error leaves the predecessor's existence unknown, so the scan must not
    assume "nothing to diff" and serve CLEAN (which would also let an oversized
    update slip past the terminal size guard below).
  - Compressed artifact size exceeds `max_artifact_size_mb` (default 50 MB)
    **and a previous version exists to diff against** — `terminal` (permanent
    for that artifact; not retried). The guard is evaluated only after the
    previous-version and cache lookups, so it fires solely when a real diff is
    being skipped.
  - The bridge returns verdict `UNKNOWN` (it could not classify the pair — e.g.
    the diff inputs were missing or the LLM response failed to parse) —
    `retryable`. UNKNOWN is a scanner error, never a clean result, and is never
    persisted to the idempotency cache.

  The error lands in `ScanReport.Errored`, so if an operator marks
  `version-diff` as `required` (see [Scanners](../scanners.md#scan-engine)),
  these conditions fail closed per `policy.on_scan_error` instead of serving
  the artifact as silently clean — in particular, the size guard closes the
  "pad an update past the limit to skip the diff" evasion. In the default
  best-effort mode the engine still degrades them to fail-open.

- **Fails open** (returns CLEAN, error **logged but not surfaced** on the
  result) when it "couldn't compare against the previous version" — a transient
  or artifact-specific condition that is not a malicious signal:
  - The previous version's blob is missing from the cache (`cache.Get` miss).
  - The previous version's cached blob fails its SHA-256 check.
  - A transient bridge call failure (gRPC error / deadline on one diff).

  These use `cleanResult`, which deliberately does **not** set
  `ScanResult.Error` — surfacing it would make the engine promote it to a
  counted scan error, failing the request closed and (pre-fix) tripping a
  scanner-wide breaker that cascaded to every artifact. See
  [ADR-013](../adr/ADR-013-enrichment-scanner-breaker-exemption.md). A sustained
  bridge outage is still caught: after N consecutive bridge errors the internal
  breaker opens and returns `throttled` (fail-closed per artifact for a required
  scanner).

  Because version-diff is **enrichment-class** it has no engine per-scanner
  circuit breaker: its genuine per-artifact errors (`retryable` UNKNOWN,
  `terminal` size guard, `throttled`) still fail closed for that one artifact
  when `required`, but can never open a scanner-wide breaker that fails
  unrelated, healthy artifacts as `overload`.

## Deployment requirement: shared cache mount

The Python `scanner-bridge` opens the **previous artifact** directly from the
gate's local filesystem (path arrives in
`ScanArtifactDiff.previous_path`). For that to work the bridge container
**must mount the gate cache read-only** at the same path the gate writes to:

```yaml
# scanner-bridge service in docker-compose / .deploy/compose.yaml
volumes:
  - bridge-socket:/tmp                         # already required for gRPC + new artifact
  - gate-cache:/var/cache/shieldoo-gate:ro     # NEW: required for version-diff (>= v2.0)
```

Without this mount, every diff scan raises `FileNotFoundError` and the bridge
returns `UNKNOWN`, which the Go scanner treats as a `retryable` scanner error
(best-effort version-diff degrades to fail-open; a `required` version-diff fails
closed). The shipped compose files
(`tests/e2e-shell/docker-compose.e2e.yml`, `docker/docker-compose.yml`,
`.deploy/compose.yaml`) already include the mount; custom deployments need
to mirror it.

The current artifact is reachable through the existing `bridge-socket:/tmp`
mount — the gate writes downloads into `/tmp/shieldoo-gate-<eco>-*.tmp`,
which is shared with the bridge.

## Configuration

```yaml
scanners:
  version_diff:
    enabled: false                  # opt-in; requires scanner-bridge with AI enabled
    mode: "shadow"                  # "shadow" | "active"
    max_artifact_size_mb: 50
    max_extracted_size_mb: 50       # bridge aggregate cap
    max_extracted_files: 5000       # bridge file-count cap
    scanner_timeout: "55s"          # must be < scanners.timeout
    bridge_socket: ""               # empty -> reuse scanners.guarddog.bridge_socket
    allowlist: []
    min_confidence: 0.6             # SUSPICIOUS below this -> CLEAN + audit_log
    per_package_rate_limit: 10      # LLM calls / hour / package; 0 = unlimited
    daily_cost_limit_usd: 5.0       # ADVISORY only in v2.0 — see "Cost monitoring" below
    circuit_breaker_threshold: 5    # consecutive failures -> 60 s degraded mode
```

> **`daily_cost_limit_usd` is advisory in v2.0.** The scanner records token usage in
> `version_diff_results.ai_tokens_used` but does **not** auto-disable on overrun.
> Use Prometheus alerting on the daily token-sum query (see "Cost monitoring" below).
> A hard cap (auto-disable on daily overrun) is deferred to v2.1.

## Verdict mapping

| AI says | Go-side mapped verdict | Notes |
|---------|------------------------|-------|
| `CLEAN` | `CLEAN` | Persisted with `ai_verdict='CLEAN'` |
| `SUSPICIOUS` (confidence ≥ `min_confidence`) | `SUSPICIOUS` | Finding severity HIGH (≥ 0.75) or MEDIUM |
| `SUSPICIOUS` (confidence < `min_confidence`) | `CLEAN` | Audit log entry `SCANNER_VERDICT_DOWNGRADED`, reason `below-min-confidence` |
| `MALICIOUS` | `SUSPICIOUS` | **Always downgraded.** Finding severity CRITICAL. Audit log entry, reason `asymmetric-diff-downgrade` |
| `UNKNOWN` (bridge could not classify the pair) | `CLEAN` payload **+ `retryable` scanner error** | **NOT persisted.** `required` version-diff fails closed (503); best-effort degrades to fail-open in the engine |

In `mode: "shadow"`, the final `ScanResult.Verdict` is forced to `CLEAN`
regardless of the mapping above. The DB row preserves the raw `ai_verdict`
and `ai_confidence` so operators can still evaluate FP/FN rate.

## Trust boundary — what leaves the gate

When the scanner runs, the bridge sends to the LLM:

- **Install hooks (full content or head+tail truncation):** `setup.py` (PyPI),
  `*.pth` (PyPI), `tools/install.ps1` / `tools/init.ps1` (NuGet),
  `ext/*/extconf.rb` (RubyGems), and the values of `package.json` `scripts.preinstall`,
  `scripts.install`, `scripts.postinstall` (NPM, surfaced as synthetic `npm:scripts/<hook>`).
- **Top-level executable code (truncated):** `.py` / `.js` / `.ts` / `.cjs` /
  `.mjs` / `.ps1` / `.sh` / `.rb` files at depth ≤ 2 from the package root.
- **File inventory and counts:** lists of added/modified/removed paths,
  ignored-path summary, install-hook paths.
- **Package metadata:** name, version, previous_version, ecosystem.

After regex redaction of a representative set of secret patterns, including:
- AWS access keys (`AKIA…`)
- GitHub tokens (`ghp_…` / `ghs_…`, plus fine-grained `github_pat_…`)
- GitLab PATs, Slack tokens
- OpenAI keys (incl. `sk-proj-…`), Stripe live/test, Twilio, Google API keys
- Generic JWTs (`eyJ…eyJ…`)
- PEM / PuTTY private keys
- Azure storage connection strings
- Generic `password=…` / `api_key=…` quoted strings

The authoritative, full pattern list lives in `scanner-bridge/diff_scanner.py` (and is mirrored in [scanners.md](../scanners.md)).

Files that are filtered (`tests/`, `docs/`, `examples/`, binary extensions)
are NOT sent — only their paths are summarized.

For deployments with strict no-egress requirements (GDPR-bound on-prem,
isolated networks): set `version_diff.enabled: false`.

## Operational queries

Cache invalidation (force re-scan after a prompt update):

```sql
DELETE FROM version_diff_results
 WHERE ai_prompt_version = ''             -- or whatever version is now stale
   AND verdict = 'CLEAN';                  -- preserve historical SUSPICIOUS for audit
```

Top SUSPICIOUS packages from the last 7 days:

```sql
SELECT a.name, COUNT(*) AS suspicious_scans, AVG(vdr.ai_confidence) AS mean_conf
  FROM version_diff_results vdr
  JOIN artifacts a ON a.id = vdr.artifact_id
 WHERE vdr.diff_at > now() - INTERVAL '7 days'
   AND vdr.verdict = 'SUSPICIOUS'
 GROUP BY a.name
 ORDER BY suspicious_scans DESC
 LIMIT 20;
```

(SQLite syntax differs slightly: replace `now() - INTERVAL '7 days'` with
`datetime('now', '-7 days')`.)

## Cost monitoring

Daily token usage / approximate spend (Postgres):

```sql
SELECT DATE(diff_at) AS day,
       SUM(ai_tokens_used) AS tokens,
       ROUND(SUM(ai_tokens_used) * 0.0000003 :: numeric, 4) AS approx_cost_usd
  FROM version_diff_results
 WHERE diff_at > now() - INTERVAL '7 days'
   AND ai_model_used IS NOT NULL  -- v2.0 rows only
 GROUP BY day ORDER BY day;
```

`daily_cost_limit_usd` in the config is **advisory** — the field gates
nothing in v2.0. Operators are expected to wire a Prometheus alert that
runs the query above and pages on overrun. A hard cap (auto-disable on
overrun) is deferred to v2.1.

## Real-world performance — production shadow window

Empirical baseline from the shadow rollout on `shieldoo-gate.cloudfield.cz`
(2026-05-01 → 2026-05-06, ≈ 5 d 19 h, 386 v2.0 scans, AI bridge
`gpt-5.4-mini`):

| Metric | Observed |
|--------|----------|
| AI verdict distribution | 363 CLEAN (94.0 %), 23 SUSPICIOUS (6.0 %), 0 MALICIOUS |
| Mean confidence (CLEAN) | 0.901 |
| Mean confidence (SUSPICIOUS) | 0.722 |
| Daily cost mean (6 days) | **$0.24** (peak day $0.70 during a CI burst) |
| Fail-open events | **0 / 386** |
| Bridge timeouts (`context deadline exceeded`) | **0 / 386** |
| Bridge OOMKills | 0 (with `mem_limit: 2g`) |
| FN coverage on synthetic-malicious set | 10 / 10 → MALICIOUS (Phase 7.5 known-malicious replay) |

The 23 SUSPICIOUS verdicts clustered into three benign-but-noteworthy
patterns rather than malware:

- **17 version downgrades** (older release than the cached newer version) —
  e.g. `xunit.* 2.9.3 → 2.9.0`, `clone 2.1.2 → 1.0.4`, `debug 4.4.3 → 3.2.7`.
  The AI correctly flags the rollback pattern; whether to block is a policy
  decision.
- **4 cross-architecture wheel rebuilds** (same version, different platform
  tag) — `pyyaml 6.0.3`, `pydantic-core 2.46.3` ×2, `cryptography 47.0.0`.
- **2 legitimate-but-signal-rich updates** — `coverage 7.12.0 → 7.13.1`
  (legit `.pth` install hook), `dotenv 16.0.3 → 16.4.7` (new vault
  crypto path).

Operator load: ~4 reviews/day during a busy week, 0–1/day during quiet
weeks. With `policy.minimum_confidence: 0.7`, only ~half of SUSPICIOUS
verdicts reach the BLOCK candidate path; the remainder are filtered by
the policy stack before reaching operators.

## The `required` breaker cascade — root cause & fix (ADR-013)

Marking version-diff `required` exposed a cascade: under an `npm ci` burst the
gate returned HTTP 503 `scanner unavailable` for **every** artifact, not just the
ones version-diff failed on. The original theory blamed version-diff's
previous-version **DB lookup** timing out under pool pressure. A faithful local
reproduction (below) **disproved that** with direct evidence:

- Postgres stayed nearly idle during the cascade: ≤3 connections (pool of 5 never
  exhausted), ≤1 active query, **zero lock waits**, zero queries slower than 1 s.
- The previous-version `SELECT` logged `previous-version lookup failed` **zero**
  times — the DB lookup never failed.
- The version-diff retryable errors that fed the breaker came from its
  `cleanResult` **fail-open** path: predecessor blob missing from cache
  (`cache get previous …: artifact not found`) and transient bridge
  `DeadlineExceeded`.

The real mechanism: version-diff returned those transient conditions as
`ScanResult{Verdict: Clean, Error: …}` *intending* to fail open, but the engine
(`scanOne`: `if err == nil && result.Error != nil { err = result.Error }`)
promoted that `Error` into a classified scan error. For the `required` version-diff
scanner it then (1) failed the request closed and (2) counted toward the
per-scanner breaker. Five transient fail-opens opened the breaker → every
subsequent artifact fast-failed `overload` → `ActionRetryLater` → 503.

**Fix ([ADR-013](../adr/ADR-013-enrichment-scanner-breaker-exemption.md)):**
(1) version-diff's `cleanResult` is now a true fail-open — it logs but does not
set `ScanResult.Error`, so the engine neither fails closed nor counts it; and
(2) version-diff is an **enrichment-class** scanner (`EnrichmentScanner`),
exempt from the engine's per-scanner breaker — its genuine errors (UNKNOWN
verdict) still fail closed *per artifact*, but can no longer open a scanner-wide
breaker that fails unrelated, healthy artifacts. Backend protection comes from
version-diff's own internal consecutive-failure breaker (`throttled`, already
excluded from the engine breaker per [ADR-012](../adr/ADR-012-fail-closed-scanner-errors.md)).

### Local reproduction harness

The default dev stack (sqlite + amd64 emulation, cold cache) does **not** reproduce
it: sqlite WAL hides lock contention, emulation serializes execution, and a cold DB
makes every package first-seen (`sql.ErrNoRows` → CLEAN, the failure path never
engages). The harness flips all three and replays the real release-CI load:

- [`docker/docker-compose.local-repro.yml`](../../docker/docker-compose.local-repro.yml)
  — Postgres backend (prod parity) with a small gate pool (`SGW_DB_POOL`, default
  5); the scanner-bridge pinned to a small CPU budget (`BRIDGE_CPUS`, default 2)
  so scans run slower under burst; native arch (`SGW_PLATFORM=""`); prod-like
  `max_concurrent_scans=32`.
- [`scripts/local-repro-versiondiff-cascade.sh`](../../scripts/local-repro-versiondiff-cascade.sh)
  — **seeds** the predecessor of every locked version in `ui/package-lock.json`
  through the gate (caches them CLEAN + records DB version rows), then runs a real
  **`npm ci` of the frontend** through the gate. With predecessors cached, every
  locked version `npm ci` pulls engages version-diff under npm's concurrent fan-out.

```bash
# AI creds: copy AI_SCANNER_* from .deploy/.env into docker/.env (the script does
# this automatically). Knobs: SKIP_UP=1, CONCURRENCY=128 (npm maxsockets),
# SGW_DB_POOL=5, BRIDGE_CPUS (raise to isolate version-diff from guarddog CPU
# starvation, lower to also stress the primary scanners).
./scripts/local-repro-versiondiff-cascade.sh
curl -s http://localhost:8080/metrics | grep -E 'circuit_breaker_state|scanner_errors_total'
```

**Before the fix**, this opened `circuit_breaker_state{scanner="version-diff"}=1`
and failed `npm ci` with 503s. **After the fix**, version-diff has no engine
breaker (that series is gone), its transient cache/bridge errors fail open, and
`npm ci` completes — even at `SGW_DB_POOL=5`. (Note: `BRIDGE_CPUS=2` separately
starves guarddog and can open the *guarddog* breaker — that is a primary
scanner legitimately failing closed under genuine CPU starvation, a different
condition from this cascade; raise `BRIDGE_CPUS` to isolate the version-diff path.)

## Retention

The table grows ~1 row per (new, prev) pair scanned. To cap unbounded
growth, [`internal/scheduler/version_diff_retention.go`](../../internal/scheduler/version_diff_retention.go)
runs a daily DELETE of `verdict = 'CLEAN'` rows older than 90 days.

- **SUSPICIOUS+ rows are kept indefinitely** as audit evidence. If you
  need to prune, do it manually with a tracked SQL DELETE.
- The retention task starts only when `scanners.version_diff.enabled: true`.
- Migration 025 adds an index on `(verdict, diff_at)` so the daily DELETE
  is cheap even at millions of rows.
- Migration 025 also adds a `scanner_version` column. New rows from v2.0+
  write `'2.0.0'`; legacy v1.x rows have NULL. Future UI filtering can
  use `WHERE scanner_version >= '2'` to discriminate.

## Migration from v1.x

The DB table `version_diff_results` is preserved. Migration 024 adds AI
columns (nullable) and an idempotency UNIQUE INDEX
`(artifact_id, previous_artifact, ai_model_used, ai_prompt_version)`. Legacy
v1.x rows have `ai_*` columns NULL — they remain visible in audit queries but
are not used by the v2.0 cache logic.

The previous heuristic config keys (`thresholds`, `entropy_sample_bytes`,
`sensitive_patterns`) are silently ignored by the new validator. Future
releases may reject them as errors after a deprecation window.

## Disabling the scanner

```yaml
scanners:
  version_diff:
    enabled: false
```

Restart the gate. No data migration is needed; the table and historical rows
remain available for audit.
