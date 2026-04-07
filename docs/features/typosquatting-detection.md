# Typosquatting & Namespace Confusion Detection

> Detect and block packages with names designed to impersonate popular libraries.

**Status:** Proposed
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

- **Scanner:** New `BuiltinTyposquatScanner` in `internal/scanner/builtin/typosquat.go`. Implements the `Scanner` interface. Runs before content-based scanners (name check is nearly instant).
- **Database:** New `popular_packages` table (ecosystem, name, rank, download_count, last_updated). New `internal_namespaces` table or config-based list.
- **Threat Feed synergy:** Typosquat detections can be auto-submitted to the threat feed contribution portal (when implemented).
- **Performance:** Name-based checks add < 1ms latency. The popular package list is loaded into memory at startup.

### Ecosystem Coverage

| Ecosystem | Typosquat Risk | Notes |
|---|---|---|
| PyPI | Very High | Flat namespace, no scopes, most targeted ecosystem |
| npm | High | Scoped packages help, but unscoped packages are vulnerable |
| RubyGems | High | Flat namespace similar to PyPI |
| NuGet | Medium | Namespace prefixes (reserved) reduce risk but are optional |
| Maven | Low | GroupId provides natural namespacing |
| Go | Low | Module paths are URLs, hard to typosquat |
| Docker | Medium | Popular image names can be squatted in public registries |

### Considerations

- **False positives:** Legitimate packages may have similar names. The confidence scoring and allowlist/override system handle this. Organizations can allowlist specific packages.
- **Maintenance:** The popular package list needs periodic refresh. Consider shipping a default list with the release and allowing custom overrides.
- **Privacy:** If fetching download stats from upstream registries, ensure no internal package names leak in the queries.
