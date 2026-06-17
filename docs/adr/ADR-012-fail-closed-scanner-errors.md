# ADR-012: Fail Closed on Required Inline Scanner Errors

Date: 2026-06-17

## Status

Accepted

## Context

Inline scanner failures previously degraded to clean verdicts, allowing artifacts to be served unscanned during scanner outages or overload. The scan engine returned `[]ScanResult` and wrapped every error as `VerdictClean`, so the policy engine and adapters could not distinguish "scanned and clean" from "never scanned".

## Decision

Inline scan completeness is explicit through `scanner.ScanReport` (`Expected`, `Results`, `Errored`, `Skipped`). Scanner errors are classified (`retryable`, `terminal`, `overload`) and retried within a bounded budget with a per-scanner circuit breaker. Scanners configured as `required` (criticality keyed by `Name()`) must produce a verdict before an artifact can become servable, unless `policy.on_scan_error` is explicitly set to `fail_open`.

The per-scanner circuit breaker applies **only to `required` scanners**. For a required scanner an open circuit yields a fast fail-closed decision (an `overload` error the policy engine maps to 503/quarantine) instead of a per-attempt timeout. Best-effort scanners fail open regardless, so short-circuiting them would carry no safety benefit and would only silently drop the data they produce (SBOM, licenses, vuln findings) for every artifact scanned during the cooldown window; they are therefore always attempted, with the bridge concurrency semaphore (`max_concurrent_scans`) remaining their overload guard.

`policy.on_scan_error` maps required scanner failures to adapter behavior:

- Pull paths return HTTP 503 with `Retry-After`.
- Docker push rejects the upload.
- Docker sync skips the artifact.

The error path persists no clean status and writes no cache entry. Every required-scanner failure emits a `SCAN_UNAVAILABLE` audit event and the `scan_error_mode_applied_total` metric regardless of mode, so a `fail_open` bypass is never silent. UNKNOWN scanner verdicts are treated as retryable scanner errors rather than clean results.

Overrides (allow/deny) and static allowlist entries intentionally bypass the availability check.

## Consequences

Scanner outages can temporarily reduce availability for artifacts that require scanner coverage. Operators can temporarily choose `fail_open`, but this emits `SCAN_UNAVAILABLE` audit events and metrics. Missing required scanners fail startup validation unless `policy.on_scan_error=fail_open`. The `policy.Engine.Evaluate(...)` method is retained as a compatibility wrapper over the new `EvaluateReport(...)` for cache/license re-evaluation paths that only have stored results.
