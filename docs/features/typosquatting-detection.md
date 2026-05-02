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
- **Adapter integration:** Both PyPI and npm adapters call `PreScanTyposquat()` before any upstream request. If the verdict is `SUSPICIOUS` or `MALICIOUS`, the adapter returns HTTP 403 immediately.
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
  3. Blocked names are persisted as `QUARANTINED` artifacts (with `version="*"` when no version is known at metadata-fetch time) so admins can review and release them from the Artifacts pane. Releasing creates a package-scoped policy override that the pre-scan consults via `engine.go:HasOverride()` on every subsequent request — see [policy.md](../policy.md#policy-overrides).
- **Maintenance:** The popular package list needs periodic refresh. Consider shipping a default list with the release and allowing custom overrides.
- **Privacy:** If fetching download stats from upstream registries, ensure no internal package names leak in the queries.
