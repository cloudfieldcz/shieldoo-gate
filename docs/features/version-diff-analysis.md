# Version Diff Analysis

> Automatically compare new package versions against previous versions to detect supply chain compromises using AI-driven semantic analysis.

**Status:** Implemented (v1.2 heuristic, rebuilt v2.0 AI-driven)
**Priority:** High
**Perspective:** Developer / Security Operations
**Operational reference:** [docs/scanners/version-diff.md](../scanners/version-diff.md)
**Rebuild rationale:** [ADR-005](../adr/ADR-005-ai-driven-version-diff.md)

## Problem

Many supply chain attacks are delivered as new versions of *existing* trusted packages. The attacker gains access to a maintainer account or CI pipeline and publishes a patched version containing malicious code alongside the legitimate functionality. Content scanners may miss these if the malicious payload is subtle or uses novel obfuscation.

Comparing a new version against the previous known-good version is one of the most effective ways to catch these attacks: legitimate updates have explainable diffs, while compromised versions often show anomalous additions (new install hooks, unexpected network calls, base64 blobs, or new files in surprising locations).

## v2.0 Solution — AI-driven semantic analysis

The v1.x static-heuristic implementation (file inventory, code-volume ratio, sensitive-pattern, entropy, dependency-newness) produced a 68.8 % suspicious-rate on legitimate mainstream releases in three weeks of production use and was retired. The v2.0 rebuild replaces all five heuristics with a single AI call:

1. The Python `scanner-bridge` extracts a `DiffPayload` from both versions: added/modified/removed file paths, install-hook contents (full or head+tail truncated), top-level executable code, and ignored-paths summary.
2. A single `gpt-5.4-mini` call (Azure OpenAI, shared with `ai-scanner`) classifies the diff as `CLEAN`, `SUSPICIOUS`, or `MALICIOUS` with a confidence score and structured findings.
3. The Go side maps the verdict, applies a deterministic `MALICIOUS → SUSPICIOUS` downgrade (rationale in ADR-005), and persists with idempotency keying on `(artifact, previous_artifact, ai_model_used, ai_prompt_version)`.

### Configuration

See [docs/configuration.md](../configuration.md) and [docs/scanners/version-diff.md](../scanners/version-diff.md) for the full reference. The minimal opt-in:

```yaml
scanners:
  version_diff:
    enabled: true
    mode: "shadow"                    # leave on "shadow" for the first 7 days
```

The previous heuristic config keys (`thresholds`, `entropy_sample_bytes`, `sensitive_patterns`) are silently ignored by the new validator.

### Operational characteristics

- **Cost.** ~$0.0017/scan worst-case; ~$0.05/day at production volume (~36 scans/day).
- **Latency.** p50 3–8 s, p99 < 30 s. Engine outer cap (`scanners.timeout`) defaults to 60 s and is invariant-checked at startup against `version_diff.scanner_timeout` (default 55 s).
- **Privacy.** Install hooks and top-level executable code from both versions leave the gate node and are sent to Azure OpenAI (after regex secret redaction). For strict no-egress deployments: `version_diff.enabled: false`.
- **Cache.** Idempotent on prompt version + model — a new prompt or model invalidates cache automatically.

### Ecosystem coverage

| Ecosystem | Status | Notes |
|---|---|---|
| PyPI | Supported | `.whl` and `.tar.gz`, install hooks: `setup.py`, `*.pth` |
| npm | Supported | `.tgz`, install hooks: `scripts.preinstall/install/postinstall` |
| NuGet | Supported | `.nupkg`, install hooks: `tools/install.ps1`, `tools/init.ps1` |
| RubyGems | Supported | `.gem`, install hooks: `ext/*/extconf.rb` |
| Maven | Supported | `.jar` source files (no decompilation) |
| Go | Supported | `.zip` source files |
| Docker | Out of scope | Handled by Trivy / image-content scanners |

### Acceptance gate

The v2.0 rebuild is considered successful only after a 7-day shadow rollout meets:

- False-positive rate < 5 % on legitimate packages
- False-negative rate 0 % on a 20-sample known-malicious test set
- p99 latency < 30 s
- Fail-open ratio < 1 %
- Daily AI cost < $0.50/day mean

These gate the flip from `mode: "shadow"` to `mode: "active"`.
