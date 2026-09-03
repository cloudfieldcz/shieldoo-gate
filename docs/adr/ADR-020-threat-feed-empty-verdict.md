# ADR-020: Verdict Semantics When the Threat Feed Is Empty

Date: 2026-09-03

## Status

**Proposed — draft, no decision taken.** Nothing in the codebase depends on this
document; `builtin-threat-feed` behaves today exactly as described under
"Current behaviour". This ADR exists to record the analysis and the questions
that must be answered before the behaviour is changed, so the next person to
notice the fail-open does not have to rediscover why the obvious fix is
dangerous.

Related: [ADR-012](ADR-012-fail-closed-scanner-errors.md) (required scanners
fail closed), [ADR-019](ADR-019-terminal-scanner-errors-block-not-retry.md)
(terminal errors block rather than retry).

## Context

`ThreatFeedChecker.Scan` (`internal/scanner/builtin/threat_feed_checker.go`)
looks up `artifact.SHA256` in the local `threat_feed` table:

```go
if err == sql.ErrNoRows {
    return scanner.ScanResult{Verdict: scanner.VerdictClean, Confidence: 1.0, …}, nil
}
```

That is correct for a healthy feed and **indistinguishable from it when the
table is empty**. With zero rows, every artifact misses, every miss is `CLEAN`
with confidence 1.0, and the scanner reports a check it is not performing.
`config.example.yaml` marks `builtin-threat-feed` as `required`, so an empty
feed also *satisfies* the required-scanner gate of ADR-012 while detecting
nothing. The failure costs coverage without costing a single blocked request,
which is precisely why it can persist unnoticed.

**It did persist.** On one production deployment the feed host
(`feed.shieldoo.io`) served the Azure App Service Environment default wildcard
certificate instead of its own, so every fetch failed TLS verification. The feed
refreshed **535 consecutive times without ever succeeding**, over three weeks,
including the initial refresh — the table was never populated at all. Each
failure produced one WARN line. Meanwhile `builtin-threat-feed` returned
`verdict=CLEAN confidence=1` for every artifact the gate served.

What has already been done (2026-09-03, no verdict change):

- `shieldoo_gate_threat_feed_*` metrics, including `..._entries`, which measures
  this state directly — see [Deployment](../deployment.md#threat-feed-health).
- The refresh log escalates to ERROR when the feed is empty, on both the
  fetch-failure and the refreshed-but-empty paths.
- `ThreatFeedChecker.HealthCheck` reports the scanner unhealthy on
  `GET /api/v1/health` when the feed is configured but empty.

The state is now observable on three surfaces. What remains open is whether it
should also change what the gate *does*.

## Candidate decision

When the local feed has zero rows, `ThreatFeedChecker.Scan` returns
`SCAN_UNAVAILABLE` instead of `CLEAN`, letting `policy.on_scan_error` decide the
outcome per ADR-012.

## Why this must not be a drive-by change

With the shipped configuration — `builtin-threat-feed: required` and
`policy.on_scan_error` unset, i.e. `quarantine` — the candidate decision
converts a **third-party TLS misconfiguration into a total block on every
artifact in every ecosystem**. Every pip install, npm install, docker pull,
NuGet restore, Maven fetch, `go mod download` and gem install through the gate
would fail, for a reason entirely outside the operator's control, until the feed
provider fixed their certificate.

For many deployments that is a strictly worse failure than the current one: the
present fail-open loses one detection layer among nine scanners, whereas the
proposed fail-closed loses the dependency pipeline outright. It is not a trade
that can be made silently on behalf of every operator, and it is not the kind of
change that belongs in a fix whose purpose was visibility.

Note also the asymmetry with ADR-012's reasoning. There, a required scanner that
*cannot run* is a genuine unknown: the artifact may or may not be malicious.
Here the scanner runs fine and answers correctly for the data it holds; what is
missing is the data. "Unable to scan" and "scanned against nothing" are not the
same failure, and mapping the second onto the first is the assumption this ADR
has to justify rather than assume.

## Questions this ADR must settle

1. **Trigger: empty table, or never-loaded?** The table is persistent and is
   what `Scan` actually consults, so `COUNT(*) == 0` is the honest condition. A
   never-loaded-this-process flag resets on every restart and would fire on a
   pod that restarts before its first refresh completes, despite a perfectly
   good table on disk.
2. **Is the answer "best-effort by default" instead?** *Probably yes.* Shipping
   `builtin-threat-feed` as `criticality: best-effort` and leaving the alarm to
   the metrics preserves the detection when the feed works, avoids the outage
   when it does not, and lets an operator who genuinely wants fail-closed opt in
   by marking it `required` themselves — which is already how criticality works
   (`docs/scanners.md`: there is no hardcoded default criticality). This
   inverts the burden onto the deployments that have consciously accepted it.
3. **Startup grace.** Between process start and the first successful refresh the
   table may legitimately be empty on a fresh install. Any trigger needs a grace
   window, or a first-run distinction, or it blocks every gate's first minutes.
4. **Interaction with the aggregator fast path.** `builtin-threat-feed` has a
   special rule in [aggregation](../scanners.md#scan-result-aggregation): a
   `MALICIOUS` verdict from it short-circuits everything else. The behaviour of
   `SCAN_UNAVAILABLE` from a scanner holding that privilege needs to be stated
   explicitly, not inherited by accident.
5. **Opt-in.** Whatever the mechanism, the safe default is arguably the current
   one, and the change should be reachable by configuration rather than imposed
   by an upgrade. An operator who upgrades the gate should not discover the new
   semantics through a production outage.

## Consequences if adopted as stated

- **Positive.** The gate stops asserting a check it is not performing. An
  organisation that treats the community feed as a control gets that control
  enforced rather than assumed.
- **Negative.** Availability of the whole proxy becomes coupled to a
  third-party feed host for deployments with `required` + `quarantine`. The
  blast radius is every ecosystem at once, and recovery is not in the
  operator's hands.
- **Neutral.** No change for `on_scan_error: fail_open` deployments beyond an
  additional `SCAN_UNAVAILABLE` audit event — which is itself useful.

## Consequences of leaving it as is (status quo)

The fail-open remains, but it is no longer silent: `..._entries == 0` alerts,
the refresh line is ERROR, and `/api/v1/health` reports the scanner unhealthy.
An operator who monitors any of the three cannot miss it; one who monitors none
of them is in the same position as before. The gate's other scanners are
unaffected — the threat feed is one layer of nine.

## References

- `internal/scanner/builtin/threat_feed_checker.go` — `Scan`, `HealthCheck`
- `internal/threatfeed/` — refresh client, metrics, escalation
- [Scanners → Feed health and failure escalation](../scanners.md#feed-health-and-failure-escalation)
- [Deployment → Threat feed health](../deployment.md#threat-feed-health)
- [ADR-012](ADR-012-fail-closed-scanner-errors.md), [ADR-019](ADR-019-terminal-scanner-errors-block-not-retry.md)
