# Version Diff Analysis

> Automatically compare new package versions against previous versions to detect suspicious changes, unexpected code injections, and supply chain compromises.

**Status:** Implemented (v1.2)
**Priority:** High
**Perspective:** Developer / Security Operations

## Problem

Many supply chain attacks are delivered as new versions of *existing* trusted packages. The attacker gains access to a maintainer account or CI pipeline and publishes a patched version containing malicious code alongside the legitimate functionality. Content scanners may miss these if the malicious payload is subtle or uses novel obfuscation.

Comparing a new version against the previous known-good version is one of the most effective ways to catch these attacks: legitimate updates have explainable diffs, while compromised versions often show anomalous additions (new install hooks, unexpected network calls, base64 blobs, or new files in surprising locations).

## Proposed Solution

Add a version diff scanner that compares each newly downloaded artifact against the most recent cached version of the same package. Flag anomalous changes with configurable sensitivity.

### Analysis Dimensions

1. **File-level diff:** New files added, files removed, files modified. Flag unexpected additions (e.g., new `.pth` file in a Python package, new `postinstall` script in npm).
2. **Code volume anomaly:** If a minor version bump adds 10× more code than the previous release, flag it. Normalize by historical release patterns for that package.
3. **Sensitive area changes:** Special attention to install-time scripts (`setup.py`, `postinstall`, `.pth`), build scripts, and configuration files. Non-executable metadata that changes on every release (Python `__init__.py`, `pyproject.toml`, `setup.cfg`; NuGet `.targets`, `.props`) is tracked at MEDIUM severity to avoid noise on routine version bumps.
4. **New dependency introduction:** If a new version adds a dependency that was never present before, flag it (especially if the new dependency is young, unpopular, or has typosquat characteristics).
5. **Entropy analysis:** High-entropy additions (packed/encrypted blobs, base64 chunks) in files that previously had low entropy.
6. **Behavioral delta:** If the sandbox scanner is enabled, compare syscall profiles between old and new versions. New network activity or file writes are strong signals.

### Key Requirements

1. **Automatic comparison:** When a new version of a previously cached package arrives, automatically compare against the most recent clean version.
2. **Smart diff engine:** Content-aware diffing (not just byte-level). Understand package structure per ecosystem.
3. **Configurable thresholds:** Allow tuning of what constitutes "anomalous" (code volume ratio, new file count, entropy delta).
4. **First-seen handling:** For packages not previously cached, skip version diff (no baseline). Optionally fetch the previous version from upstream for comparison.
5. **Results integration:** Diff findings feed into the standard scan result aggregation. Anomalous diffs raise confidence on other scanner findings.

### Configuration

```yaml
scanners:
  version_diff:
    enabled: true
    fetch_previous: false             # Fetch previous version from upstream if not cached
    max_artifact_size_mb: 100         # Skip diff for very large artifacts
    thresholds:
      code_volume_ratio: 5.0          # Flag if new version is 5x larger
      max_new_files: 20               # Flag if more than 20 new files added
      entropy_delta: 2.0              # Flag high-entropy additions
    sensitive_patterns: []            # Extra glob patterns to flag (beyond built-in per-ecosystem list)
```

Built-in sensitive file severity (per ecosystem):

| Ecosystem | CRITICAL (install hooks) | MEDIUM (metadata / module code) | HIGH (other sensitive) |
|---|---|---|---|
| PyPI | `setup.py`, `*.pth` | `__init__.py`, `pyproject.toml`, `setup.cfg` | — |
| NPM | `preinstall*`, `postinstall*`, `install*` | — | `package.json` |
| NuGet | `install.ps1`, `init.ps1` | `*.targets`, `*.props` | — |
| Maven | — | — | `pom.xml`, `*.sh` |
| RubyGems | `extconf.rb` | — | `Rakefile` |
| Go | — | — | `go.mod` |

### How It Fits Into the Architecture

- **Scanner:** New `VersionDiffScanner` in `internal/scanner/versiondiff/`. Implements `Scanner` interface. Queries the cache and database for the previous version of the same package.
- **Cache interaction:** Reads the previous version from the cache store (any backend). Extracts and compares contents in a temporary directory.
- **Database:** Uses existing `artifacts` table to find previous versions. Stores structured diff outputs in `version_diff_results` table. Note: the `artifact_id` column does NOT have a foreign key constraint on `artifacts(id)` because the version-diff scanner runs during the scan pipeline before the current artifact is persisted. The `previous_artifact` column does reference `artifacts(id)` since it's retrieved from an existing DB row.
- **Admin UI:** Show a "Changes from previous version" section on the artifact detail page with a visual diff summary.

### Ecosystem Coverage

| Ecosystem | Diff Feasibility | Notes |
|---|---|---|
| PyPI | High | `.whl` and `.tar.gz` are easily extractable |
| npm | High | `.tgz` tarballs, well-structured `package/` directory |
| NuGet | High | `.nupkg` is a ZIP with predictable structure |
| RubyGems | High | `.gem` is a tar with data.tar.gz inside |
| Maven | Medium | `.jar` is a ZIP; class files need decompilation for meaningful diff |
| Go | High | `.zip` with source files |
| Docker | Low-Medium | Layer-based; meaningful diff requires layer unpacking |

### Considerations

- **Performance:** Extracting and comparing two versions adds latency. Run asynchronously (like the sandbox scanner) so it does not block the download path. Store results and apply them retroactively.
- **Storage:** Requires the previous version to still be in cache. If cache eviction removes it, diff is skipped. Consider pinning the latest clean version per package for diff purposes.
- **Semantic understanding:** A raw diff cannot distinguish "developer added a legitimate build optimization" from "attacker injected a payload." Combine with AI scanner findings for best results.
- **Version ordering:** Use ecosystem-specific version comparison (PEP 440 for Python, semver for npm, etc.) to determine which version is "previous."
