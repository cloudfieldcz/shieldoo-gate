# ADR-005 — AI-driven version-diff scanner replaces heuristic implementation

**Date:** 2026-04-30
**Status:** Accepted
**Supersedes:** None
**Reference:** [`docs/scanners/version-diff.md`](../scanners/version-diff.md) — live spec, config knobs, verdict mapping, real-world performance numbers from the production shadow window.

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
