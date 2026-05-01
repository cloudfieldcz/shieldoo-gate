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
- Skipped (returns CLEAN) when:
  - The package name is in the configured `allowlist`.
  - Compressed artifact size exceeds `max_artifact_size_mb` (default 50 MB).
  - No previous CLEAN/SUSPICIOUS version exists in the artifacts table.
  - An idempotent cache hit is found in `version_diff_results` for the
    `(new artifact, previous artifact, model, prompt version)` tuple.
  - The per-package rate limiter has exhausted the hourly quota.
  - The consecutive-failure circuit breaker is open.

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

Without this mount, every diff scan raises `FileNotFoundError`, the bridge
returns `UNKNOWN`, and the Go scanner fail-opens. The shipped compose files
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
> A hard cap is tracked in [docs/plans/follow-ups.md](../plans/follow-ups.md) for v2.1.

## Verdict mapping

| AI says | Go-side mapped verdict | Notes |
|---------|------------------------|-------|
| `CLEAN` | `CLEAN` | Persisted with `ai_verdict='CLEAN'` |
| `SUSPICIOUS` (confidence ≥ `min_confidence`) | `SUSPICIOUS` | Finding severity HIGH (≥ 0.75) or MEDIUM |
| `SUSPICIOUS` (confidence < `min_confidence`) | `CLEAN` | Audit log entry `SCANNER_VERDICT_DOWNGRADED`, reason `below-min-confidence` |
| `MALICIOUS` | `SUSPICIOUS` | **Always downgraded.** Finding severity CRITICAL. Audit log entry, reason `asymmetric-diff-downgrade` |
| `UNKNOWN` (parse error, timeout, fail-open) | `CLEAN` (fail-open) | **NOT persisted** — cache integrity protected |

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

After regex redaction of:
- AWS access keys (`AKIA…`)
- GitHub tokens (`ghp_…` / `ghs_…`)
- Generic JWTs (`eyJ…eyJ…`)
- PEM private keys
- Azure storage connection strings
- Generic `password=…` / `api_key=…` quoted strings

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
overrun) is tracked in [docs/plans/follow-ups.md](../plans/follow-ups.md)
for v2.1.

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
