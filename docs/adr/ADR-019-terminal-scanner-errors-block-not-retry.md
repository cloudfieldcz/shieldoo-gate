# ADR-019: Terminal Scanner Errors Block Instead of Retry

Date: 2026-07-29

## Status

Accepted. Amends [ADR-012](ADR-012-fail-closed-scanner-errors.md).

## Context

[ADR-012](ADR-012-fail-closed-scanner-errors.md) established that a `required` scanner which cannot produce a verdict fails closed, and that `policy.on_scan_error=quarantine` (the default) surfaces this on pull paths as **HTTP 503 with `Retry-After`**. That mapping was applied uniformly to every classified error kind.

It is wrong for `terminal`. ADR-012 itself defines a `terminal` error as "a permanent property of one artifact (e.g. too large to scan, unsupported format)" and notes it "is not retried". Answering `retry_later` therefore makes a promise the gate knows to be false: no amount of retrying will change the outcome.

This surfaced in production on 2026-07-29. Every fetch of `opencv-contrib-python` 4.10.0.84 returned 503:

1. The wheel is ~65 MB and the sdist ~150 MB, exceeding `scanners.version_diff.max_artifact_size_mb: 50`.
2. version-diff's compressed-size guard runs *after* the previous-version lookup, so it fires only once a sibling distribution of the same package is already cached. A first-seen oversized package exits CLEAN before reaching it — which is why the package installed fine for months and then broke.
3. The guard returned `ErrKindTerminal`, landing in `ScanReport.Errored`.
4. version-diff is `criticality: required` in that deployment, and `policy.on_scan_error` was unset (→ `quarantine`).
5. The policy engine returned `ActionRetryLater` → HTTP 503 + `Retry-After`.

Consequences observed: `pip` retried indefinitely and never succeeded; each attempt made the gate re-download ~65 MB and re-run the entire scanner suite (trivy ~3.6 s, ai-scanner ~5.9 s, guarddog, osv, …) to recompute a verdict that was structurally predetermined. `paddlepaddle` 3.2.2, `pymupdf` 1.27.2, and `opencv-python-headless` 4.13.0.92 hit the same path. Because the response was a 5xx, it read to operators as a transient scanner outage rather than a permanent policy outcome.

## Decision

Under `policy.on_scan_error=quarantine`, a `terminal` error from a `required` scanner returns **`block` (HTTP 403)** instead of `retry_later` (HTTP 503).

| Error kind | `quarantine` mode | Rationale |
|---|---|---|
| `retryable`, `overload` | `retry_later` (503) | Transient backend failure; retrying can succeed |
| `throttled` | `retry_later` (503) | Local backpressure; the quota resets on its own |
| `terminal` | `block` (403) | Permanent for this artifact; nothing to come back for |

Supporting rules:

- **Terminal wins over sibling errors.** If one required scanner fails terminally, the artifact can never pass, so `block` takes precedence over a concurrent `retryable` or `throttled` failure.
- **`fail_open` is unchanged.** It remains an explicit operator escape hatch: a terminal error there still allows the artifact and still emits `SCAN_UNAVAILABLE`.
- **Best-effort scanners are unchanged.** A terminal error from a best-effort scanner still degrades to fail-open in the engine.
- **The audit row records the mode actually applied.** A terminal failure under `quarantine` is logged as `{"kind":"terminal","mode":"block"}`, not `"mode":"retry_later"`, so the forensic trail matches the response the client received.

This preserves fail-closed semantics in full. In particular the size guard keeps closing the "pad a package past the size limit to skip the diff" evasion — the artifact is still refused, just with an honest status code.

## Consequences

- Permanently unscannable artifacts now fail fast and stop generating retry storms and redundant scan work.
- Serving such an artifact requires a deliberate operator action: an allow override, or raising the responsible scanner's limit (e.g. `scanners.version_diff.max_artifact_size_mb`). A 50 MB cap rejects common ML/CV wheels once a second distribution is cached, so deployments that proxy those ecosystems should raise it.
- Clients see 403 rather than 503 for this class of failure. Callers that special-case 5xx as "retry later" and 4xx as "give up" now behave correctly instead of looping.
- On the rescan path a `PENDING_SCAN` artifact whose required scanner fails terminally reaches `QUARANTINED` (with `rescan_due_at` cleared) instead of being re-queued on every cycle. It becomes visible in the UI and clearable via override. Already-`CLEAN` artifacts are unaffected: the rescan scheduler only selects `PENDING_SCAN` rows.
- `throttled` deliberately keeps its 503 mapping despite ADR-012 grouping it with `terminal` as "not retried". That grouping is about the *engine's* internal retry budget and breaker accounting, not about what the client should do — a rate-limit quota does reset, so a client retry can succeed.

## References

- [Scanner failure policy](../policy.md#terminal-errors-are-never-retryable)
- [version-diff scanner](../scanners/version-diff.md)
- [ADR-013: enrichment scanner breaker exemption](ADR-013-enrichment-scanner-breaker-exemption.md)
- E2E regression cover: `tests/e2e-shell/test_oversized_artifact.sh`
