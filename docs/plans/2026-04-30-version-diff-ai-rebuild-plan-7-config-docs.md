# Version-Diff AI Rebuild — Phase 7: Configuration + documentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reshape `config.example.yaml` for the new schema, write the ADR explaining the asymmetric MALICIOUS-downgrade decision, write/refresh `docs/scanners/version-diff.md`, and link from `docs/index.md`. No code changes.

**Architecture:** Pure docs work. The previous `version_diff:` block in `config.example.yaml` listed dead heuristic options. We replace it with the new options + a prominent comment explaining `mode: shadow` as the default for first activation.

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

### Task 1: Update `config.example.yaml`

**Files:**
- Modify: [config.example.yaml:135-150](../../config.example.yaml#L135-L150)

- [ ] **Step 1: Replace the `version_diff:` block**

In [config.example.yaml](../../config.example.yaml), locate the `version_diff:` block (currently lines 135–150) and replace it with:

```yaml
  # AI-driven version diff scanner (v2.0+). Compares each new package version
  # against the most recent CLEAN/SUSPICIOUS cached version, sends both to the
  # scanner-bridge over gRPC, and asks the LLM (gpt-5.4-mini default) whether
  # the changes show malicious supply-chain intent. Replaces the heuristic
  # version_diff scanner — config keys with `thresholds:` / `entropy_sample_bytes`
  # / `sensitive_patterns:` are now ignored.
  #
  # FIRST ACTIVATION: leave `mode: "shadow"` for at least 7 days. The scanner
  # will run on every applicable artifact and persist results to
  # `version_diff_results`, but its verdict will be forced to CLEAN so the
  # policy engine ignores it. Operators can then evaluate FP/FN rate and AI
  # cost before flipping to `mode: "active"`.
  #
  # TRUST BOUNDARY: install hooks and top-level executable code from BOTH
  # versions of the package leave the gate node and are sent to Azure OpenAI
  # for analysis (after secret-pattern redaction). For on-prem deployments
  # with strict no-egress requirements, set `enabled: false`.
  version_diff:
    enabled: false                        # opt-in; requires scanner-bridge with AI enabled
    mode: "shadow"                        # "shadow" (no policy effect) | "active" (verdict reaches policy)
    max_artifact_size_mb: 50              # skip diff for artifacts larger than this (compressed)
    max_extracted_size_mb: 50             # bridge: max aggregate bytes read across all members
    max_extracted_files: 5000             # bridge: max member count
    scanner_timeout: "55s"                # must be < scanners.timeout (engine outer cap, default 60 s)
    bridge_socket: ""                     # empty → reuse scanners.guarddog.bridge_socket
    allowlist: []                         # package names to skip (FP suppression)
    min_confidence: 0.6                   # SUSPICIOUS below this is downgraded to CLEAN with audit_log entry
    per_package_rate_limit: 10            # max LLM calls per package per hour; 0 = unlimited
    daily_cost_limit_usd: 5.0             # alerting / future hard-cap; soft signal in v2.0
    circuit_breaker_threshold: 5          # consecutive bridge errors trigger 60 s degraded mode
```

- [ ] **Step 2: Bump engine `scanners.timeout` default to 60 s (MANDATORY)**

The engine outer timeout in [cmd/shieldoo-gate/main.go:248](../../cmd/shieldoo-gate/main.go#L248) currently reads:

```go
scanTimeout := parseDuration(cfg.Scanners.Timeout, 30*time.Second)
```

The 30 s default is incompatible with `version_diff.scanner_timeout: 55s` — every version-diff scan would be killed by the outer cap before the LLM finished. Bump it to 60 s:

```go
scanTimeout := parseDuration(cfg.Scanners.Timeout, 60*time.Second)
```

Also document the invariant in `config.example.yaml`:

```yaml
scanners:
  timeout: "60s"                          # outer cap per scanner per artifact; default 60 s.
                                          # Invariant: must be ≥ version_diff.scanner_timeout + 5s buffer.
  # ...
```

Add a startup-time validation (in `internal/config/config.go` `Validate` or a new `validateScannerTimeoutInvariant` helper) that fails if `cfg.Scanners.Timeout < cfg.Scanners.VersionDiff.ScannerTimeout + 5*time.Second` whenever version-diff is enabled. Example:

```go
// In Validate(), after validateVersionDiff:
if c.Scanners.VersionDiff.Enabled {
    outer, _ := time.ParseDuration(c.Scanners.Timeout)
    inner, _ := time.ParseDuration(c.Scanners.VersionDiff.ScannerTimeout)
    if outer == 0 {
        outer = 60 * time.Second
    }
    if inner == 0 {
        inner = 55 * time.Second
    }
    if outer < inner + 5*time.Second {
        return fmt.Errorf("config: scanners.timeout (%s) must be >= scanners.version_diff.scanner_timeout (%s) + 5s", outer, inner)
    }
}
```

Also adjust the `parseDuration(cfg.Scanners.AI.Timeout, 15*time.Second)` line ([main.go:197](../../cmd/shieldoo-gate/main.go#L197)) only if needed — the existing AI scanner timeout of 15 s sits comfortably under both engines' caps, no change required.

(No commit yet — combined with the docs.)

---

### Task 2: Write the ADR

**Files:**
- Create: `docs/adr/ADR-005-ai-driven-version-diff.md`

- [ ] **Step 1: Write the ADR**

Existing ADRs in [docs/adr/](../../docs/adr/) follow the format `ADR-NNN-title.md`. The latest is ADR-004; this is ADR-005.

Create [docs/adr/ADR-005-ai-driven-version-diff.md](../../docs/adr/ADR-005-ai-driven-version-diff.md):

```markdown
# ADR-005 — AI-driven version-diff scanner replaces heuristic implementation

**Date:** 2026-04-30
**Status:** Accepted
**Supersedes:** None
**Related:** [Plan: 2026-04-30-version-diff-ai-rebuild](../plans/2026-04-30-version-diff-ai-rebuild.md)

## Context

The original `version-diff` scanner (versioned `1.x`, shipped in v1.1) used
five static heuristics — file inventory delta, code-volume ratio, sensitive
file pattern match, byte entropy, and dependency newness — to flag suspicious
package version changes. After three weeks of production data on
`shieldoo-gate.cloudfield.cz` (2026-04-08 to 2026-04-29) the scanner produced
**520 SUSPICIOUS verdicts on 756 scans (68.8% suspicious-rate)**. Manual
review of the top flagged packages (`system.text.json` 45×, `numpy`,
`microsoft.extensions.logging.abstractions`, `cffi`, `pandas`, `starlette`)
showed that **all** were legitimate mainstream releases. The scanner was
disabled in production on 2026-04-29.

Root cause: structural diff without semantic understanding cannot distinguish
"normal release adds a feature" from "release injects a malicious install
hook". Both produce file-count changes, dependency churn, and entropy shifts.
The static `sensitive_file` pattern in particular flagged routine metadata
files (`__init__.py`, `package.json`, `pom.xml`, `*.targets`) on every release.

## Decision

Rebuild the `version-diff` scanner as an **AI-only** semantic analyzer:

- The Python scanner-bridge extracts a `DiffPayload` (added / modified /
  removed files, install-hook classification, top-level code categorization,
  ignored-paths summary) for both versions.
- A single-pass call to `gpt-5.4-mini` (Azure OpenAI, shared with `ai-scanner`)
  evaluates whether the diff shows malicious supply-chain intent.
- The verdict is mapped on the Go side, with `MALICIOUS` always downgraded to
  `SUSPICIOUS` (rationale below).
- All static heuristic code is deleted (`internal/scanner/versiondiff/diff.go`,
  `extractor.go`, ~840 lines).

The scanner name (`version-diff`), config block (`scanners.version_diff`),
DB table (`version_diff_results`), and gRPC service stay. Migration 024 adds
AI-specific columns; the legacy heuristic columns become nullable so historical
rows survive.

## Consequences

### Asymmetric MALICIOUS downgrade vs `ai-scanner`

`ai-scanner` analyzes a **single version's** install hooks and DOES NOT
downgrade `MALICIOUS` — its verdict reaches policy as `MALICIOUS`. The new
`version-diff` analyzes a **cross-version diff**; structurally weaker signal.

We deliberately downgrade `MALICIOUS` → `SUSPICIOUS` for `version-diff`:

- A diff-only signal cannot distinguish "version 2.0 introduces a legitimate
  major refactor that touches install hooks" from "version 2.0 is a typosquat
  that injects a payload". The LLM is more likely to hallucinate `MALICIOUS`
  when faced with high-volume legitimate changes.
- `version-diff` runs in parallel with `ai-scanner` (single-version), `osv`,
  `reputation`, `guarddog`, and others. A single-source `MALICIOUS` from a
  weak signal would be over-strong; downgrading to `SUSPICIOUS` lets the
  policy engine consider the full evidence set.
- For audit, the raw AI verdict is preserved in column `ai_verdict`; the
  downgrade itself emits a `SCANNER_VERDICT_DOWNGRADED` audit log entry.

The previous comment in `internal/scanner/versiondiff/scanner.go:204-205`
("Per project conventions, scanner heuristics never escalate to MALICIOUS")
was self-imposed — there is no codified project convention on this. The new
rule is documented here: **diff-based scanners downgrade MALICIOUS;
single-version content scanners do not**.

### Operational surface

- **Cost.** ~$0.0017/scan worst-case (gpt-5.4-mini at 32k input + 1k output
  tokens). Production data shows ~36 scans/day average → **~$0.05/day** /
  $1.50/month. Idempotency cache ensures restarts and re-scans don't burn
  tokens. `daily_cost_limit_usd: 5.0` (soft cap; hard-stop circuit breaker
  is a follow-up).
- **Latency.** p50 3–8 s, p99 < 30 s. Engine runs scanners in parallel, so
  the new latency floor only matters when version-diff is the slowest scanner
  on a given artifact.
- **Privacy.** Install hooks and top-level executable code from both versions
  leave the gate node and are sent to Azure OpenAI (after regex secret
  redaction). For on-prem deployments with strict no-egress requirements,
  `version_diff.enabled: false` is the recommended setting. A local-LLM
  alternative is out of scope.
- **Cache invalidation.** The idempotency UNIQUE INDEX includes
  `(artifact_id, previous_artifact, ai_model_used, ai_prompt_version)`. A new
  model or prompt content automatically invalidates cache without manual
  flushing.

### Negative consequences

- **Bridge dependency.** version-diff now requires the scanner-bridge with
  `AI_SCANNER_ENABLED=true`. Without it, the scanner fails open (CLEAN) on
  every call.
- **Latency increase for shadow-mode artifacts.** During the 7-day shadow
  window, scans that previously took 1–3 s (heuristic) now take 3–30 s. The
  policy ignores the verdict so client-perceived latency is unaffected if the
  engine timeout is set correctly.
- **Anti-prompt-injection prompt is required.** `version_diff_analyst.txt`
  includes a role-lock guard. The existing `security_analyst.txt` (used by
  `ai-scanner`) does NOT. This is a known gap with `ai-scanner`; closing it
  is out of scope here.

## Alternatives considered

- **Hybrid (heuristic gate + AI deep-look)**: keep the cheap heuristic to
  early-CLEAN obvious cases, only call AI for SUSPICIOUS-by-heuristic. Rejected
  because the heuristic's 68.8% FP rate makes it a poor first stage — the AI
  would be invoked on most scans anyway, and we'd carry maintenance cost on
  two scanners.
- **Local LLM**: vLLM / llama.cpp running in the gate container. Rejected for
  v2.0 because it introduces deployment complexity (GPU sizing, model
  updates) and the cost of Azure OpenAI is acceptable for the early-adopter
  audience. Reconsider for an on-prem-friendly v2.1.
- **Sandbox-augmented diff**: run install hooks in a sandbox and compare
  syscall traces. Rejected because the sandbox infrastructure does not yet
  exist in shieldoo-gate; a separate ADR should propose it.

## Acceptance gate

The rebuild is considered successful only after a 7-day shadow-mode rollout
in production satisfies all of:

- False-positive rate < 5 % on legitimate packages
- False-negative rate 0 % on a 20-sample known-malicious test set
- p99 latency < 30 s
- Fail-open ratio < 1 %
- Daily cost < $0.50/day mean

These criteria gate the flip from `mode: "shadow"` to `mode: "active"`.
```

(No commit yet.)

---

### Task 3: Write the scanner doc

**Files:**
- Create: `docs/scanners/version-diff.md`

- [ ] **Step 1: Verify `docs/scanners/` exists**

```bash
ls docs/scanners/ 2>/dev/null || mkdir -p docs/scanners/
```

If the directory doesn't exist, create it. (Some references in the analysis assume it does — verify before writing.)

- [ ] **Step 2: Write the doc**

Create [docs/scanners/version-diff.md](../../docs/scanners/version-diff.md):

```markdown
# Version-Diff Scanner

> **Status:** v2.0 (AI-driven) — replaces the v1.x static heuristic implementation.
> See [ADR-005](../adr/ADR-005-ai-driven-version-diff.md) for the rebuild rationale.

The `version-diff` scanner detects malicious supply-chain attacks by comparing
each new package version against its most recent CLEAN/SUSPICIOUS cached
predecessor. Both versions are sent to the Python `scanner-bridge` over gRPC,
where extraction and an LLM call (gpt-5.4-mini default) classify the changes
as `CLEAN`, `SUSPICIOUS`, or `MALICIOUS`. The Go side maps the verdict to a
`scanner.Verdict`, persists the result, and applies a deliberate
`MALICIOUS → SUSPICIOUS` downgrade (see "Verdict mapping" below).

## When does it run?

- Per-artifact, in parallel with all other enabled scanners.
- Skipped (returns CLEAN) when:
  - The package name is in the configured `allowlist`.
  - Compressed artifact size exceeds `max_artifact_size_mb` (default 50 MB).
  - No previous CLEAN/SUSPICIOUS version exists in the artifacts table.
  - An idempotent cache hit is found in `version_diff_results` for the
    `(new artifact, previous artifact, model, prompt version)` tuple.
  - The per-package rate limiter has exhausted the hourly quota.
  - The consecutive-failure circuit breaker is open.

## Configuration

```yaml
scanners:
  version_diff:
    enabled: false                  # opt-in; requires scanner-bridge with AI enabled
    mode: "shadow"                  # "shadow" | "active"
    max_artifact_size_mb: 50
    max_extracted_size_mb: 50       # bridge aggregate cap
    max_extracted_files: 5000       # bridge file-count cap
    scanner_timeout: "55s"          # must be < scanners.timeout
    bridge_socket: ""               # empty → reuse scanners.guarddog.bridge_socket
    allowlist: []
    min_confidence: 0.6             # SUSPICIOUS below this → CLEAN + audit_log
    per_package_rate_limit: 10      # LLM calls / hour / package; 0 = unlimited
    daily_cost_limit_usd: 5.0
    circuit_breaker_threshold: 5    # consecutive failures → 60 s degraded mode
```

## Verdict mapping

| AI says | Go-side mapped verdict | Notes |
|---------|------------------------|-------|
| `CLEAN` | `CLEAN` | Persisted with `ai_verdict='CLEAN'` |
| `SUSPICIOUS` (confidence ≥ `min_confidence`) | `SUSPICIOUS` | Finding severity HIGH (≥ 0.75) or MEDIUM |
| `SUSPICIOUS` (confidence < `min_confidence`) | `CLEAN` | Audit log entry `SCANNER_VERDICT_DOWNGRADED`, reason `below-min-confidence` |
| `MALICIOUS` | `SUSPICIOUS` | **Always downgraded.** Finding severity CRITICAL. Audit log entry, reason `asymmetric-diff-downgrade` |
| `UNKNOWN` (parse error, timeout, fail-open) | `CLEAN` (fail-open) | **NOT persisted** — cache integrity protected |

In `mode: "shadow"`, the final `ScanResult.Verdict` is forced to `CLEAN`
regardless of the mapping above. The DB row preserves the raw `ai_verdict`
and `ai_confidence` so operators can still evaluate FP/FN rate.

## Trust boundary — what leaves the gate

When the scanner runs, the bridge sends to the LLM:

- **Install hooks (full content or head+tail truncation):** `setup.py` (PyPI),
  `*.pth` (PyPI), `tools/install.ps1` / `tools/init.ps1` (NuGet),
  `ext/*/extconf.rb` (RubyGems), and the values of `package.json` `scripts.preinstall`,
  `scripts.install`, `scripts.postinstall` (NPM, surfaced as synthetic `npm:scripts/<hook>`).
- **Top-level executable code (truncated):** `.py` / `.js` / `.ts` / `.cjs` /
  `.mjs` / `.ps1` / `.sh` / `.rb` files at depth ≤ 2 from the package root.
- **File inventory and counts:** lists of added/modified/removed paths,
  ignored-path summary, install-hook paths.
- **Package metadata:** name, version, previous_version, ecosystem.

After regex redaction of:
- AWS access keys (`AKIA…`)
- GitHub tokens (`ghp_…` / `ghs_…`)
- Generic JWTs (`eyJ…eyJ…`)
- PEM private keys
- Azure storage connection strings
- Generic `password=…` / `api_key=…` quoted strings

Files that are filtered (`tests/`, `docs/`, `examples/`, binary extensions)
are NOT sent — only their paths are summarized.

For deployments with strict no-egress requirements (GDPR-bound on-prem,
isolated networks): set `version_diff.enabled: false`.

## Operational queries

Cache invalidation (force re-scan after a prompt update):

```sql
DELETE FROM version_diff_results
 WHERE ai_prompt_version = ''             -- or whatever version is now stale
   AND verdict = 'CLEAN';                  -- preserve historical SUSPICIOUS for audit
```

Top SUSPICIOUS packages from the last 7 days:

```sql
SELECT a.name, COUNT(*) AS suspicious_scans, AVG(vdr.ai_confidence) AS mean_conf
  FROM version_diff_results vdr
  JOIN artifacts a ON a.id = vdr.artifact_id
 WHERE vdr.diff_at > now() - INTERVAL '7 days'
   AND vdr.verdict = 'SUSPICIOUS'
 GROUP BY a.name
 ORDER BY suspicious_scans DESC
 LIMIT 20;
```

(SQLite syntax differs slightly: replace `now() - INTERVAL '7 days'` with
`datetime('now', '-7 days')`.)

## Migration from v1.x

The DB table `version_diff_results` is preserved. Migration 024 adds AI
columns (nullable) and an idempotency UNIQUE INDEX
`(artifact_id, previous_artifact, ai_model_used, ai_prompt_version)`. Legacy
v1.x rows have `ai_*` columns NULL — they remain visible in audit queries but
are not used by the v2.0 cache logic.

The previous heuristic config keys (`thresholds`, `entropy_sample_bytes`,
`sensitive_patterns`) are silently ignored by the new validator. Future
releases may reject them as errors after a deprecation window.

## Disabling the scanner

```yaml
scanners:
  version_diff:
    enabled: false
```

Restart the gate. No data migration is needed; the table and historical rows
remain available for audit.
```

(No commit yet.)

---

### Task 4: Update `docs/index.md`

**Files:**
- Modify: [docs/index.md](../../docs/index.md)

- [ ] **Step 1: Add a link to the new scanner doc**

Locate the section that lists the per-scanner docs (or, if there's no per-scanner doc page list, add a brief mention under "Scanners"). Append a bullet:

```markdown
- [Version-Diff Scanner](scanners/version-diff.md) — AI-driven cross-version semantic analysis (replaces v1.x heuristic, see [ADR-005](adr/ADR-005-ai-driven-version-diff.md))
```

If `docs/index.md` already groups scanner docs under a heading, place the bullet there. If not, place it in the "Documentation" group near `Scanners`.

- [ ] **Step 2: Verify all internal links resolve**

```bash
grep -E "scanners/version-diff|ADR-005" docs/index.md docs/scanners/version-diff.md docs/adr/ADR-005-ai-driven-version-diff.md docs/plans/2026-04-30-version-diff-ai-rebuild.md
```

Expected: each referenced file exists, no broken markdown link.

---

### Task 5: Smoke-build and commit

- [ ] **Step 1: Build + lint**

```bash
make build
make lint
```

Expected: clean.

- [ ] **Step 2: Run docs-sanity grep**

```bash
# No leftover references to dead config keys in active docs
grep -rn "entropy_sample_bytes\|builtinSensitivePatterns\|VersionDiffThresholds" docs/ \
    | grep -v "docs/plans/" \
    | grep -v "docs/adr/ADR-005" \
    | head
# Expected: empty (or only grep -v'd plan + ADR mentions are OK)
```

- [ ] **Step 3: Commit**

```bash
git add config.example.yaml \
        docs/scanners/version-diff.md \
        docs/adr/ADR-005-ai-driven-version-diff.md \
        docs/index.md
# If main.go was tweaked for the scanners.timeout default change, include:
git add cmd/shieldoo-gate/main.go 2>/dev/null
git commit -m "docs: ADR-005 + scanner doc + config.example for AI-driven version-diff"
```

---

## Verification — phase-end

```bash
# All artifacts in place
ls docs/adr/ADR-005-ai-driven-version-diff.md \
   docs/scanners/version-diff.md \
   config.example.yaml

# Build + lint clean
make build && make lint

# Tests still green
make test
```

## What this phase ships

- `config.example.yaml`: new `version_diff:` block (mode/shadow default, all v2.0 fields, dropped legacy keys).
- `docs/adr/ADR-005-ai-driven-version-diff.md`: rationale, downgrade asymmetry justification, alternatives, acceptance gate.
- `docs/scanners/version-diff.md`: operational reference (verdict mapping, trust boundary, queries, migration notes).
- `docs/index.md`: link to the new scanner doc.

## Risks during this phase

- **`scanners.timeout` default mismatch.** The Go default is `30 s` ([cmd/shieldoo-gate/main.go:248](../../cmd/shieldoo-gate/main.go#L248)) but the analysis assumes 60 s. The plan flags this — pick one of the two options in Task 1 Step 2 and apply consistently.
- **`docs/scanners/` may not exist yet.** Task 3 Step 1 covers creating it.
- **ADR numbering.** Confirm the latest ADR before naming this one ADR-005. As of 2026-04-30 the highest is ADR-004; if a concurrent branch adds ADR-005, rename to ADR-006.
