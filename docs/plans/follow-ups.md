# Follow-ups

Tracked items deferred from larger initiatives. Not bugs — known gaps with
explicit "ship later" decisions. Each entry links to its source plan and
states what is currently shipped vs. what's missing.

## Version-diff v2.0 follow-ups

### `daily_cost_limit_usd` hard cap (target: v2.1)

**Source:** [Phase 6a](./2026-04-30-version-diff-ai-rebuild-plan-6a-go-skeleton-config.md), [Phase 9](./2026-04-30-version-diff-ai-rebuild-plan-9-retention-cleanup.md) Task 5.

**Currently shipped:** the config field `scanners.version_diff.daily_cost_limit_usd`
is parsed and persisted, and per-scan token usage is recorded in
`version_diff_results.ai_tokens_used`. Operators can compute spend with the
SQL query in [`docs/scanners/version-diff.md`](../scanners/version-diff.md#cost-monitoring).

**Missing:** the scanner does not auto-disable itself or refuse new scans
when daily spend exceeds the limit. Today the field is advisory and only
useful as a Prometheus alert threshold.

**Why deferred:** the cost-tracking surface area touches scheduling, the
breaker, and the engine integration — better landed as a focused v2.1 task
than bolted on during the initial rollout.

**What ships in v2.1:** a daily cost accumulator (in-memory + reset at
00:00 UTC) that gates `Scan()` similarly to the consecutive-failure breaker.
On overrun: log + return `VerdictClean` for the rest of the day, emit a
metric `version_diff_cost_breaker_open=1`.

### Configurable retention window (no target date)

**Source:** [Phase 9](./2026-04-30-version-diff-ai-rebuild-plan-9-retention-cleanup.md).

**Currently shipped:** 90-day hard-coded retention for CLEAN rows in
`internal/scheduler/version_diff_retention.go` (`VersionDiffRetentionDays`).

**Missing:** the retention window is not configurable.

**Why deferred:** no operator has asked. If multiple deployments need
different windows (e.g. high-volume environments wanting 30 days), promote
the constant to `scanners.version_diff.retention_days` with a default of 90.

### UI filter for v1.x vs v2.0+ rows (out of scope for backend)

**Source:** [Phase 9](./2026-04-30-version-diff-ai-rebuild-plan-9-retention-cleanup.md).

**Currently shipped:** `scanner_version` column on `version_diff_results`
(migration 025). New rows write `'2.0.0'`; legacy rows are NULL.

**Missing:** the admin UI does not yet filter or label rows by scanner
version. UI work tracked separately.
