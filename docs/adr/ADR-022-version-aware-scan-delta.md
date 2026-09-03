# ADR-022 — Version-aware scan delta, CVE-level resolution

**Status:** Accepted
**Date:** 2026-09-03
**Related:** [ADR-021](ADR-021-version-aware-cve-suppression.md) (the suppression half of
the same problem), [ADR-007](ADR-007-vulnerability-scan.md)

## Context

`component.ComputeDelta` (`internal/component/delta.go`) diffs a scan run against its
predecessor to produce `new_critical_count` / `new_high_count`, the `scan.new_critical`
and `scan.new_high` alerts, and a list of resolved CVE ids. It keyed both halves of that
diff on `f.CVEID + "|" + f.PackageName` — no version.

[ADR-021](ADR-021-version-aware-cve-suppression.md) made suppression version-aware. That
is what made the delta's version-blindness reachable: `gate-image` now legitimately holds
two findings sharing a `(cve, package)` key — the bundled `aquasec/trivy` binary's copy
of `stdlib`, suppressed by a version-pinned ignore, and our own binary's copy, not
suppressed. Two defects followed.

1. **A regression on our own copy was not reported as new.** The previous run's key set
   already contained `CVE-…|stdlib` from the suppressed vendored copy, so a `stdlib` CVE
   appearing at *our* build's version was silently treated as already-known. It was
   counted in `critical_count` and shown in the Active tab, but `scan.new_critical`
   never fired — the alert path was blind on exactly the code path ADR-021 was written to
   keep visible.

2. **Resolved-CVE reporting was order-dependent.** The key map stored one representative
   `*ScanFinding` per key, last write wins, and the resolved branch then tested
   `!p.IsSuppressed` on whichever of the pair happened to be visited last.

Separately, the `"|"` join is the same delimiter footgun ADR-021's implementation removed
from the ignore path: package names and versions come from operator-uploaded CycloneDX, so
a package literally named `stdlib|1.24.6` produces the same key as `stdlib` at version
`1.24.6`. Here the consequence is a misreported alert rather than a suppressed finding,
but there is no reason to keep the shape.

## Decision

The two halves of the delta are keyed at **different granularities**, on purpose.

| Half | Key | Over |
|---|---|---|
| `NewCritical` / `NewHigh` | `(cve_id, package_name, package_version)` — the comparable struct `findingKey` | all previous findings, suppressed included |
| `ResolvedCVEs` | `cve_id` alone | **unsuppressed** findings only |

A finding is **new** when its exact triple was absent from the previous run. A CVE is
**resolved** when it had at least one unsuppressed finding on the previous run and has
none now, at any version of any package. `ResolvedCVEs` is sorted and deduplicated.

The key is a comparable struct, not a delimited string, for the reason ADR-021 gives for
`IgnoreKey`: a struct key cannot collide.

### What this changes when a package is bumped

Bumping a package that **still carries** the CVE re-alerts it against the new version and
does **not** report it resolved. Bumping a package that **drops** the CVE reports it
resolved and alerts nothing.

The re-alert is a false positive by choice. The alternative — treating a CVE as
already-known for a package at every version — is precisely defect 1 above: it is what let
a suppressed vendored copy mask a regression in our own binary. On a security alert an
extra line costs attention; a missing one costs coverage.

Keeping `ResolvedCVEs` at CVE granularity is what stops the two halves contradicting each
other. Measured on the triple, every bump would report the CVE resolved *and* new in the
same run, and an operator reading `scan.new_critical` next to a "resolved" list would have
no way to tell a fix from a version move. Measured on the CVE, "resolved" means the one
thing an operator acts on: nothing actionable is left for this component.

A finding that was suppressed on the previous run and is unsuppressed now is **not**
reported as new — its triple was present. An ignore expiring is a lifecycle event with its
own audit row (`ignore.expired`), not a new vulnerability.

## Consequences

- **`scan.new_critical` / `scan.new_high` fire more often.** Any dependency bump that
  carries an unfixed CRITICAL or HIGH forward re-alerts. Deployments that bump frequently
  and patch slowly will see repeat alerts for the same CVE id at successive versions. The
  alert payload (`metadata_json`) already carries `{"cve":…,"pkg":…,"version":…}`, so the
  version is what distinguishes them.
- **`new_critical_count` on `scan_runs` counts vulnerable artefacts, not distinct CVEs.**
  The same CVE on two versions of the same package counts twice. This matches how
  `critical_count` has always been computed (it counts finding rows), so the two columns
  stay comparable.
- **Resolution is coarser than suppression.** ADR-021 made an *ignore* reach exactly one
  version; this ADR makes *resolution* span all of them. That asymmetry is deliberate —
  they answer different questions ("what did the operator decide to stop counting" versus
  "is there still anything to act on") — but it means a CVE fixed on one package while
  still open on another is not reported resolved until both are clear.
- **`ResolvedCVEs` is deterministic.** It was previously produced by map iteration. It is
  now sorted, so the same pair of runs always yields the same list. Nothing consumes it in
  the product today; it is part of the `Delta` contract and is what a resolved-CVE alert
  or digest would be built from.

## Alternatives rejected

- **Key both halves on the triple.** Every bump would report the CVE new *and* resolved.
  Self-contradictory output on the one surface an operator reads to decide whether a
  release improved anything.
- **Key "new" on `(cve, package)` over unsuppressed previous findings only.** This also
  fixes the suppressed-vendored-copy miss and produces no bump noise, so it is the
  tempting answer. It was rejected because it still loses the general case: if the
  vendored copy's CVE is *not* suppressed — nobody has raised an ignore yet — a
  regression on our own copy is again masked by an already-present `(cve, package)`. It
  fixes the instance, not the class.
- **Suppress the bump re-alert with a "version changed" marker on the alert.** More
  surface (a new field, a UI affordance, a migration if it is to be queryable) to make an
  alert quieter. Not worth it before anyone has complained about the volume; the version
  is already in the payload.
