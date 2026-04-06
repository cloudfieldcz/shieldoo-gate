# Policy Engine

> How Shieldoo Gate decides whether to allow, block, or quarantine artifacts.

## Overview

The policy engine (`internal/policy/`) is the decision layer between scan results and the adapter's response. It evaluates aggregated scan results against configured rules and returns one of four actions: **allow**, **block**, **quarantine**, or **warn**.

The engine consists of two stages:

1. **Aggregation** (`aggregator.go`) — Combines multiple scanner results into a single verdict
2. **Evaluation** (`engine.go`) — Applies policy rules to the aggregated verdict

## Evaluation Order

Policy evaluation follows a strict priority order — **first match wins**:

```
1. Database overrides (highest priority)
   ↓ no match
2. Static allowlist entries
   ↓ no match
3. Verdict-based rules
   ↓ no match
4. Default: ALLOW
```

### Step 1: Database Overrides

The engine queries the `policy_overrides` table for active (non-revoked, non-expired) overrides matching the artifact's ecosystem, name, and version:

```sql
SELECT COUNT(*) FROM policy_overrides
WHERE ecosystem = ? AND name = ? AND revoked = 0
  AND (expires_at IS NULL OR expires_at > ?)
  AND (scope = 'package' OR (scope = 'version' AND version = ?))
```

If a matching override exists, the artifact is **allowed** immediately regardless of scan results. This is how false positives are handled.

**Fail-open:** Database query errors do not block artifacts — the engine silently proceeds to the next priority level.

### Step 2: Static Allowlist

The allowlist is defined in configuration as a list of strings with format `"{ecosystem}:{name}[:=={version}]"`:

```yaml
policy:
  allowlist:
    - "pypi:litellm:==1.82.6"    # Allow specific version
    - "npm:lodash"                # Allow all versions (if no version specified)
```

Parsed at engine initialization into `AllowlistEntry` structs. If the artifact matches an allowlist entry, it is **allowed** immediately. Note: the `==` prefix is optional — `"pypi:litellm:1.82.6"` works the same as `"pypi:litellm:==1.82.6"`.

### Step 3: Verdict Rules

The aggregated verdict is compared against two configurable thresholds:

| Config Key | Default | Action |
|---|---|---|
| `policy.block_if_verdict` | `MALICIOUS` | Return **BLOCK** |
| `policy.quarantine_if_verdict` | `SUSPICIOUS` | Return **QUARANTINE** |

If omitted from the config file, these defaults apply. If the verdict matches `block_if_verdict`, the artifact is blocked. If it matches `quarantine_if_verdict`, it is quarantined. Otherwise, it is allowed.

### Step 4: Default

If none of the above rules match, the artifact is **allowed**.

## Scan Result Aggregation

Before policy evaluation, the aggregator (`internal/policy/aggregator.go`) combines multiple `ScanResult` values into a single `AggregatedResult` with one verdict and all findings merged.

### Aggregation Rules (in priority order)

1. **Threat feed fast-path** — If any result from scanner `builtin-threat-feed` has verdict `MALICIOUS`, return `MALICIOUS` immediately. No confidence check applied. This ensures known-malicious packages from the community feed are blocked without delay.

2. **Skip errored results** — Results where `Error != nil` are treated as `CLEAN` (fail-open).

3. **Skip low-confidence results** — Results with `Confidence < MinConfidence` (default 0.7) are ignored.

4. **Highest verdict wins** — `MALICIOUS > SUSPICIOUS > CLEAN`. All findings from qualifying results are merged.

5. **No valid results** — If all results were filtered out, verdict is `CLEAN`.

### Confidence Threshold

The `policy.minimum_confidence` setting (default `0.7`) filters out scanner results that are not confident enough to act on. This prevents low-confidence false positives from triggering blocks.

The threat feed checker is exempt from this threshold — it bypasses confidence checks entirely.

## Policy Actions

| Action | HTTP Response | Artifact Status | Audit Event | Description |
|---|---|---|---|---|
| **ALLOW** | Serve artifact | `CLEAN` | `SERVED` | Artifact passes all checks; cached and served |
| **BLOCK** | HTTP 403 | `QUARANTINED` | `BLOCKED` | Artifact is malicious; rejected and quarantined |
| **QUARANTINE** | HTTP 403 | `QUARANTINED` | `QUARANTINED` | Artifact is suspicious; stored but not served |
| **ALLOW_WITH_WARNING** | Serve artifact + `X-Shieldoo-Warning` header | `CLEAN` | `ALLOWED_WITH_WARNING` | v1.2: Artifact has MEDIUM severity findings but allowed by balanced/permissive mode |
| **WARN** | Serve artifact | `CLEAN` | `TAG_MUTATED` | Used by tag mutability detection; artifact served but alert fired |

Both BLOCK and QUARANTINE result in the artifact being marked as `QUARANTINED` in the database. The difference is in the audit event type and the reason logged. ALLOW_WITH_WARNING serves the artifact but records it in the audit log for security team review.

## Policy Overrides

Policy overrides allow administrators to create exceptions for artifacts that were incorrectly flagged by scanners.

### Override Scopes

| Scope | Description | Example |
|---|---|---|
| `version` | Applies to a specific version only | Allow `pypi:requests:2.32.3` |
| `package` | Applies to all versions of a package | Allow all versions of `pypi:requests` |

### Override Lifecycle

```
Created ──▶ Active ──▶ Revoked (soft-delete)
               │
               └──▶ Expired (if expires_at is set)
```

- **Active overrides** take effect immediately on the next artifact request
- **Revoked overrides** are soft-deleted (`revoked=true`, `revoked_at` set) — they remain in the database for audit purposes but no longer match
- **Expired overrides** automatically stop matching after `expires_at` passes
- Override matching in the policy engine is performed via a direct SQL query in `engine.go:hasDBOverride()`, not the Go `PolicyOverride.Matches()` method. The query checks ecosystem, name, version (if scope=version), non-revoked, and non-expired

### Override API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/overrides` | List overrides (paginated, filterable by active status) |
| `POST` | `/api/v1/overrides` | Create override (specify ecosystem, name, version, scope, reason) |
| `DELETE` | `/api/v1/overrides/{id}` | Revoke override (soft-delete) |
| `POST` | `/api/v1/artifacts/{id}/override` | Create override from artifact (convenience shortcut) |
| `POST` | `/api/v1/artifacts/{id}/release` | Release artifact from quarantine — also creates a version-scoped override |

The release endpoint is the primary UI action for quarantined artifacts. It sets the artifact status to `CLEAN` and creates a policy override so the artifact is not re-quarantined on the next scan.

### Deduplication

A partial unique index on `policy_overrides(ecosystem, name, version, scope) WHERE revoked = FALSE` prevents duplicate active overrides. All override creation endpoints (including release) use `INSERT ... ON CONFLICT DO NOTHING` + `SELECT` for idempotent behavior — calling release or override multiple times on the same artifact reuses the existing active override.

### Audit Trail

Override operations are logged in the audit log:
- `OVERRIDE_CREATED` — when a new override is created via the override endpoints
- `RELEASED` — when an artifact is released (which also creates an override)
- `OVERRIDE_REVOKED` — when an override is revoked

## Example Scenarios

### Known malicious package (threat feed hit)

```
Artifact: pypi:litellm:1.82.7
Scanner: builtin-threat-feed → MALICIOUS (confidence: 1.0)
Aggregation: fast-path → MALICIOUS
Policy: MALICIOUS matches block_if_verdict → BLOCK
Result: HTTP 403, status QUARANTINED, audit event BLOCKED
```

### Suspicious install hook (multiple scanner signals)

```
Artifact: pypi:new-package:0.1.0
Scanner: builtin-install-hook → SUSPICIOUS (confidence: 0.85)
Scanner: guarddog → SUSPICIOUS (confidence: 0.9)
Scanner: trivy → CLEAN (confidence: 1.0)
Aggregation: highest verdict = SUSPICIOUS
Policy: SUSPICIOUS matches quarantine_if_verdict → QUARANTINE
Result: HTTP 403, status QUARANTINED, audit event QUARANTINED
```

### False positive with override

```
Artifact: pypi:internal-tool:1.0.0
Scanner: builtin-obfuscation → SUSPICIOUS (confidence: 0.75)
Policy step 1: DB override exists for pypi:internal-tool (scope=package) → ALLOW
Result: Artifact served, status CLEAN, audit event SERVED
```

### Low confidence result filtered

```
Artifact: npm:some-lib:3.2.1
Scanner: builtin-exfil → SUSPICIOUS (confidence: 0.4)
Scanner: osv → CLEAN (confidence: 1.0)
Aggregation: exfil result filtered (0.4 < 0.7 threshold), remaining = CLEAN
Policy: CLEAN below action thresholds → ALLOW
Result: Artifact served, status CLEAN, audit event SERVED
```

## Policy Tiers (v1.2)

Policy tiers introduce configurable policy modes that control how SUSPICIOUS verdicts are handled. MALICIOUS and CLEAN verdicts behave identically across all modes.

### Modes

| Mode | SUSPICIOUS (HIGH+) | SUSPICIOUS (MEDIUM) | SUSPICIOUS (LOW/INFO) |
|---|---|---|---|
| **strict** (default) | QUARANTINE | QUARANTINE | QUARANTINE |
| **balanced** | QUARANTINE | AI Triage or QUARANTINE (degraded) | ALLOW + warning |
| **permissive** | QUARANTINE | ALLOW + warning | ALLOW + warning |

Configure via `policy.mode` or `SGW_POLICY_MODE` environment variable.

### Scanner Categories

Scanners are classified into categories that affect how their findings' severity is interpreted:

| Category | Scanners | Min Effective Severity |
|---|---|---|
| **behavioral** | guarddog, ai-scanner, exfil-detector, install-hook, pth-inspector, obfuscation | **HIGH** (floor) |
| **vulnerability** | osv, trivy | actual severity from findings |
| **integrity** | hash-verifier, threat-feed | N/A (produce MALICIOUS, not SUSPICIOUS) |

The **behavioral floor** is a critical security mechanism: behavioral scanner findings are elevated to at least HIGH effective severity. This prevents severity-downgrade attacks where a crafted package triggers SUSPICIOUS+MEDIUM from a behavioral scanner and would otherwise slip through balanced/permissive mode.

### Effective Severity

`MaxEffectiveSeverity()` calculates the highest severity among findings from scanners that contributed to the SUSPICIOUS verdict (CLEAN scanner findings are ignored). The behavioral floor is applied before comparison.

**Edge case:** SUSPICIOUS without findings (anomaly) defaults to HIGH effective severity, ensuring quarantine.

### AI Triage (balanced mode)

In balanced mode, MEDIUM severity findings from vulnerability scanners are sent to an AI triage endpoint (gRPC scanner-bridge) for contextual evaluation. The AI considers package popularity, CVE exploitability, and fix availability.

- **Timeout:** 5s, no retries on inline path
- **Cache:** Results cached in `triage_cache` DB table (7-day TTL default)
- **Circuit breaker:** 5 consecutive failures → 60s cooldown
- **Rate limiter:** 10 calls/minute (configurable)
- **Fail-safe:** Any error → fallback QUARANTINE (never ALLOW)

When AI triage is disabled in balanced mode, MEDIUM severity falls back to QUARANTINE (degraded balanced = strict for MEDIUM tier).

### Two Confidence Thresholds

- `policy.minimum_confidence` (default 0.7) — **Scanner confidence**: filters scan results with low confidence in the aggregator
- `policy.ai_triage.min_confidence` (default 0.7) — **Triage confidence**: requires minimum trust in AI triage decisions

These are independent — scanner confidence determines whether a scan result enters aggregation; triage confidence determines whether an AI triage decision is trusted.

### Startup Warnings

| Condition | Log Level | Message |
|---|---|---|
| `mode=permissive` | WARN | Permissive mode is active — SUSPICIOUS with MEDIUM severity served without review |
| `mode=balanced`, `ai_triage.enabled=false` | INFO | Balanced mode with AI triage disabled — MEDIUM severity will be quarantined |
| `mode` set + `quarantine_if_verdict` set | WARN | policy.mode is set — policy.quarantine_if_verdict is ignored |

### Mode vs quarantine_if_verdict

When `mode` is set (non-empty, non-"strict"), it takes priority over `quarantine_if_verdict`. The old config field is ignored and a startup warning is logged.

When `mode` is empty or absent, `quarantine_if_verdict` applies as before (backward compatible = strict behavior).

### Alert Integration

`ALLOWED_WITH_WARNING` is a filterable event type for webhook/Slack/email alerts:

```yaml
alerts:
  webhook:
    enabled: true
    on: ["BLOCKED", "QUARANTINED", "ALLOWED_WITH_WARNING"]
```

### Client-Facing Behavior

Artifacts allowed with warning are served normally (HTTP 200) with an additional header:

```
X-Shieldoo-Warning: MEDIUM vulnerability detected; see admin dashboard for details
```

Standard package managers (pip, npm, docker) ignore this header, but custom tooling can parse it.

## Tag Mutability Detection

The tag mutability subsystem (`internal/adapter/mutability.go`) is part of the policy layer but operates independently from the verdict-based engine. It detects when an upstream registry tag or version resolves to a different digest than previously observed — a potential indicator of supply chain compromise.

### Configuration

```yaml
policy:
  tag_mutability:
    enabled: true
    action: "quarantine"     # "quarantine" | "warn" | "block"
    exclude_tags:            # Tags known to be mutable (skip checks)
      - "latest"
      - "nightly"
      - "dev"
    check_on_cache_hit: false  # Check on every cache hit (adds ~50-200ms latency)
```

### Detection Flow

1. On cache hit, if `check_on_cache_hit` is enabled, the adapter resolves the upstream tag to its current digest.
2. The digest is compared against the `tag_digest_history` table.
3. If a new digest is observed for a previously-seen tag:
   - **`quarantine`** (default) — Quarantine the new artifact, keep old cached as CLEAN
   - **`block`** — Return 403 immediately
   - **`warn`** — Serve the artifact but fire `TAG_MUTATED` audit event and alert
4. Excluded tags (e.g., `latest`) are skipped.

### Actions

| Action | Behavior | Audit Event |
|---|---|---|
| `quarantine` | New artifact quarantined, old cached served | `TAG_MUTATED` |
| `block` | Return HTTP 403 | `TAG_MUTATED` |
| `warn` | Serve artifact, fire alert | `TAG_MUTATED` |
