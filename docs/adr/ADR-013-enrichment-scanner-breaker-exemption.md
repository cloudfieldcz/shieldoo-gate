# ADR-013: Enrichment-Class Scanners Are Exempt From the Per-Scanner Circuit Breaker

Date: 2026-06-18

## Status

Accepted (extends [ADR-012](ADR-012-fail-closed-scanner-errors.md))

## Context

Running `version-diff` as a `required` scanner produced a cascade: under an
`npm ci` burst the gate started returning HTTP 503 `scanner unavailable` for
**every** artifact, not just the ones version-diff actually failed on. The
working theory (see the prod incident notes) was that version-diff's
previous-version **DB lookup** was timing out under connection-pool pressure and
those retryable errors were opening the engine's per-scanner circuit breaker.

A faithful local reproduction (Postgres backend, small gate pool, native arch,
seeded predecessors, real `npm ci` of the UI tree — see
`scripts/local-repro-versiondiff-cascade.sh`) **disproved the DB theory** with
direct evidence:

- During the cascade, Postgres held ≤3 connections (pool of 5 never exhausted),
  ≤1 active query at a time, **zero lock waits**, and **zero queries slower than
  1 second**. The database was nearly idle.
- The previous-version `SELECT` (`scanner.go`) logged `previous-version lookup
  failed` **zero** times. The DB lookup never failed.
- The version-diff retryable errors that fed the breaker actually came from its
  `cleanResult` **fail-open** path: predecessor blob missing from the cache
  (`cache get previous …: artifact not found`) and transient bridge
  `DeadlineExceeded`.

The real mechanism is a contract mismatch. version-diff returns those transient
conditions as `ScanResult{Verdict: Clean, Error: …}`, intending to *fail open*
(it logs `version-diff: fail-open`). But the engine's `scanOne` promotes any
non-nil `result.Error` into a classified scan error
(`if err == nil && result.Error != nil { err = result.Error }`). For the
`required` version-diff scanner that promoted error (a) failed the request closed
and (b) counted toward the per-scanner breaker (ADR-012). Five such transient
fail-opens opened the breaker, after which every subsequent artifact fast-failed
`overload` → `ActionRetryLater` → 503 — failing unrelated, healthy artifacts.

This contract is correct for *primary* scanners (guarddog, ai-scanner): a
`Clean+Error` result there genuinely means "couldn't scan this artifact's
content" and should fail closed when required. version-diff is different: it is
an **enrichment** scanner that compares a new version against a *previously
cached* one. Its failures are artifact-specific (one package's predecessor is
uncacheable, one diff is anomalous) or transient-backend — never a signal that
the scanner is unhealthy for *all* traffic.

## Decision

Two changes, mapped to the two failure modes above.

1. **version-diff's `cleanResult` is a true fail-open.** It no longer sets
   `ScanResult.Error`; the underlying error is logged for observability and
   dropped from the result. The engine therefore sees a clean result, does not
   promote an error, does not fail the request closed, and does not count it
   toward any breaker. This covers the conditions version-diff already classified
   as fail-open: predecessor cache-miss, SHA-256 mismatch on the *previous*
   version, and a transient bridge call failure. Conditions that must genuinely
   fail **closed** for a required scanner — UNKNOWN verdict, the size-evasion
   guard, the per-package rate limit, and version-diff's own internal
   consecutive-failure breaker — continue to use `scanErrorResult`.

2. **Enrichment-class scanners are exempt from the engine's per-scanner circuit
   breaker.** A scanner may implement `scanner.EnrichmentScanner`
   (`EnrichmentClass() bool`); the engine creates no breaker for it. Such a
   scanner is still invoked on every artifact and still fails closed **per
   artifact** when required (its `retryable`/`UNKNOWN` error lands in
   `ScanReport.Errored`), but a burst of artifact-specific failures can no longer
   open a scanner-wide breaker that fast-fails unrelated artifacts as `overload`.
   Backend protection for version-diff is provided by its **own** internal
   consecutive-failure breaker (which returns `throttled`, already excluded from
   the engine breaker per ADR-012), so the engine breaker was both redundant and
   harmful for it.

The marker is independent of criticality: an enrichment scanner can still be
`required`. Primary required scanners (guarddog, ai-scanner, builtin-threat-feed)
keep the engine breaker unchanged.

## Consequences

- The `npm ci` cascade no longer occurs: version-diff transient fail-opens are
  invisible to the engine, and its genuine per-artifact errors fail only their
  own artifact closed. Confirmed against the local reproduction at a pool size
  (5) that previously tripped it.
- `shieldoo_gate_circuit_breaker_state{scanner="version-diff"}` is no longer
  exported — version-diff has no engine breaker. Backend health is observable via
  version-diff's internal breaker and `scanner_errors_total{scanner="version-diff"}`.
- Security posture: version-diff's *intended* fail-open conditions now actually
  fail open even when it is `required`. This matches the scanner's design intent
  (cross-version diff is structurally weaker; MALICIOUS is already asymmetrically
  downgraded to SUSPICIOUS). A genuinely undecidable diff (UNKNOWN) still fails
  closed per artifact. A sustained bridge outage still fails closed via the
  internal breaker (`throttled` → 503) for a required version-diff.
- The engine contract for primary scanners is unchanged: `Clean+Error` from a
  required primary scanner still fails closed and still feeds its breaker.
