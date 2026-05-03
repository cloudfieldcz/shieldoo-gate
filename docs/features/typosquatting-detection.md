# Typosquatting & Namespace Confusion Detection

> Detect and block packages with names designed to impersonate popular libraries.

**Status:** Implemented (v1.2)
**Priority:** High
**Perspective:** CISO / Security Operations

## Problem

Typosquatting is one of the most common supply chain attack vectors. Attackers publish packages with names nearly identical to popular libraries (e.g., `reqeusts` instead of `requests`, `lodsah` instead of `lodash`). Dependency confusion and namespace hijacking (publishing internal package names to public registries) are related threats. Shieldoo Gate currently detects malicious *content* inside packages, but does not flag suspicious *naming patterns* — the earliest and cheapest signal of an attack.

In 2024–2026, thousands of typosquat packages were discovered across PyPI, npm, and RubyGems. Many were caught only after installations occurred. A proxy-level check would block these before any code executes.

## Proposed Solution

Add a new built-in scanner (`builtin-typosquat`) that evaluates package names against known popular packages and organizational namespace rules.

### Detection Strategies

1. **Edit distance analysis** — Levenshtein distance against the top N packages per ecosystem (configurable, default: top 5000). Flag packages within distance ≤ 2 of a popular name.
2. **Character substitution patterns** — Detect homoglyph substitution (`l` → `1`, `o` → `0`), hyphen/underscore swaps (`python-dateutil` vs `python_dateutil`), prefix/suffix additions (`python-requests-lib`).
3. **Namespace confusion** — Maintain an internal package name registry. If a package name matches an internal namespace but is being fetched from a public registry, flag it. Configuration via allowlist of internal prefixes/scopes (e.g., `@mycompany/`, `mycompany-`).
4. **Starjacking / popularity mismatch** — Cross-reference package metadata (age, download count, maintainer) with the popular package it resembles. A week-old package named `requets` with 12 downloads is high risk.
5. **Combosquatting** — Detect concatenation of popular names with common suffixes: `-utils`, `-helper`, `-lib`, `-dev`, `-tool`, `-sdk`.

### Key Requirements

1. **Popular package index:** Maintain a periodically refreshed list of top packages per ecosystem (from PyPI stats, npm download counts, etc.). Store in database with refresh cycle (default: weekly).
2. **Configurable sensitivity:** Threshold settings for edit distance, minimum popularity rank to protect, custom blocklist of known-bad patterns.
3. **Internal namespace registry:** Organizations define their internal package prefixes. Any public package matching these triggers a high-confidence alert.
4. **Verdict:** Return `SUSPICIOUS` (confidence 0.8+) for likely typosquats, `MALICIOUS` (confidence 0.95) when combined with other malicious signals (e.g., typosquat name + install hook + obfuscation).

### Configuration

```yaml
scanners:
  typosquat:
    enabled: true
    top_packages_count: 5000          # Protect top N packages per ecosystem
    max_edit_distance: 2              # Flag names within this distance
    refresh_interval: "168h"          # Weekly refresh of popular package list
    internal_namespaces:              # Organization's internal package prefixes
      - "@mycompany/"
      - "mycompany-"
      - "internal-"
    combosquat_suffixes:              # Additional suffixes to check
      - "-utils"
      - "-helper"
      - "-lib"
```

### How It Fits Into the Architecture

- **Scanner:** `BuiltinTyposquatScanner` in `internal/scanner/builtin/typosquat.go`. Implements the `Scanner` interface.
- **Pre-scan gate:** The typosquat check runs as a **pre-scan before contacting upstream** via `Engine.PreScanTyposquat()`. This is critical because:
  - For PyPI downloads, a typosquat package that doesn't exist upstream would cause a 502 if the proxy tried to fetch first.
  - For npm metadata requests (`GET /{package}`), the scan pipeline doesn't run at all — only tarball downloads trigger full scanning. The pre-scan catches typosquats at the metadata level.
  - Blocking before upstream fetch avoids leaking internal package queries to public registries.
- **Adapter integration:** All fetch-protocol adapters — PyPI, npm, NuGet, Maven, RubyGems, gomod, and Docker (pull only) — call `PreScanTyposquat()` before any upstream request. If the verdict is `SUSPICIOUS` or `MALICIOUS`, the adapter returns HTTP 403 immediately. **gomod** is the exception: it returns **HTTP 410 Gone** (the GOPROXY convention for "module not available — do not retry credentials"), and only the `.info` / `.mod` / `.zip` endpoints are gated; `/@v/list` and `/@latest` pass through to keep `go mod tidy` fast on the name-enumeration phase. **Docker push** to internal namespaces is also intentionally not gated — push is an authenticated developer act and naming is operator-controlled.
- **Database:** `popular_packages` table (ecosystem, name, rank, download_count, last_updated). Seeded additively from embedded data on **every startup** — `INSERT … ON CONFLICT (ecosystem, name) DO NOTHING` ensures new entries shipped in a release propagate to existing DBs without manual intervention, while existing rows (including future UI-managed edits) are preserved. Strategy 1 (exact-match) short-circuits the edit-distance check for any name in `popular_packages`, so listing two real-but-similar packages (e.g., `vite` and `vitest`, `next` and `nest`) prevents false positives.
- **Threat Feed synergy:** Typosquat detections can be auto-submitted to the threat feed contribution portal (when implemented).
- **Performance:** Name-based checks add < 1ms latency. The popular package list is loaded into memory at startup.

### Ecosystem Coverage

| Ecosystem | Typosquat Risk | Notes | Seed coverage (2026-Q1) |
|---|---|---|---|
| PyPI | Very High | Flat namespace, no scopes, most targeted ecosystem | ~150 names |
| npm | High | Scoped packages help, but unscoped packages are vulnerable | ~170 names (incl. scoped) |
| RubyGems | High | Flat namespace similar to PyPI | ~85 names |
| NuGet | Medium | Namespace prefixes (reserved) reduce risk but are optional | ~75 names |
| Maven | Low | GroupId provides natural namespacing | ~75 GA-pairs (`groupId:artifactId`) |
| Go | Low | Module paths are URLs, hard to typosquat | ~80 module paths |
| Docker | Medium | Popular image names can be squatted in public registries | ~25 names |

### Considerations

- **False positives:** Legitimate packages may have similar names (e.g. `vitest` vs `vite`, `nest` vs `next`, `nx-js` vs `rxjs`). Three layers of mitigation:
  1. Both names are added to `popular_packages` so Strategy 1 short-circuits before edit-distance check.
  2. Operators can extend `scanners.typosquat.allowlist` in `config.yaml` for any case the seed doesn't cover.
  3. Blocked names are persisted as `QUARANTINED` artifacts with `version="*"` (always — typosquat detection is name-based, so the override scope is always package-wide regardless of whether the original request carried a version). Admins review and release them from the Artifacts pane. Releasing creates a package-scoped policy override that the pre-scan consults via `engine.go:HasOverride()` on every subsequent request — see [policy.md](../policy.md#policy-overrides). To apply a tighter scope, revoke the package override and create a manual version-scoped override.

### Producer-side dedup and audit growth

`PersistTyposquatBlock` collapses repeated probes for the same artifact ID within `scanners.typosquat.persist_dedup_window_seconds` (default 300, i.e. 5 minutes) into a single set of DB writes. The 403 response is **not** affected — every probe is still blocked at HTTP. The dedup only suppresses the synthetic-row insert and the `scan_results` / `audit_log` writes that follow it. This is the in-process growth control for `audit_log`, which stays append-only per the security invariant in [CLAUDE.md](../../CLAUDE.md). `scan_results` rows are additionally pruned by a daily scheduler (90-day window, but rows currently referenced by `artifact_status.last_scan_id` are retained even when older).

When an active policy override suppresses a typosquat block, the audit `EVENT_SERVED` entry includes `{"override_id": <id>}` in `metadata_json`. Operators can use this to trace which override let a given request through.

The public 403 response body says only `"typosquatting detected"` and does **not** include the popular package name the seed matched against. The full description ("`X is within edit distance N of popular package Y`") is preserved in `scan_results.findings_json` and `audit_log.reason` for admin investigation. The canonical query for typosquat-block evidence is `audit_log.event_type='BLOCKED' AND reason LIKE 'typosquat%'`, not HTTP status (relevant because gomod returns 410 instead of 403).

**Operator troubleshooting (gomod 410):** End developers running `go mod tidy` against a typosquat-named module see "module not found / not available". Operators should check the Artifacts pane for a `go:<modulePath>:*` entry — its presence indicates the gate blocked the fetch. The audit-log query above gives the same evidence in textual form. Releasing the entry creates a package-scoped override that the pre-scan honors on the next attempt.

**Override revoke vs. cached blocks:** Revoking a typosquat override is async with respect to in-flight requests. Once revoked, subsequent requests re-evaluate the typosquat pre-scan; cached `QUARANTINED` synthetic rows are left as-is until the operator re-blocks via the Artifacts pane. The full-scan adapter path (post-download) re-evaluates overrides via `policy.Evaluate` on every request.
- **Maintenance:** The popular package list needs periodic refresh. Consider shipping a default list with the release and allowing custom overrides.
- **Privacy:** If fetching download stats from upstream registries, ensure no internal package names leak in the queries.
