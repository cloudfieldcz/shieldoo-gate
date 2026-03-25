---
name: security-code-review
description: Use when code changes touch security-critical paths - scanner integration, cache storage, artifact serving, policy enforcement, authentication, or gRPC bridge - to dispatch a security-focused code review before merging
---

# Security Code Review

## Overview

Dispatch the security-reviewer agent to review code changes that touch security-critical paths. Complements the standard code-reviewer by focusing specifically on supply chain security, artifact integrity, and the project's security invariants.

**Core principle:** Every change to a security-critical path gets a security review, not just a code quality review.

## When to Use

**Mandatory — dispatch security-reviewer:**
- Changes to `internal/scanner/` (scanner integrations)
- Changes to `internal/cache/` (artifact storage)
- Changes to `internal/adapter/` (protocol adapters — handle untrusted upstream data)
- Changes to `internal/policy/` (policy engine — enforcement decisions)
- Changes to `internal/api/` (REST API — authentication, authorization)
- Changes to `scanner-bridge/` (gRPC bridge — inter-process trust boundary)
- Changes to `internal/scheduler/` (rescan scheduler — quarantine decisions)
- Changes to `docker/` or `helm/` (deployment — secrets, network exposure)
- Any change that modifies artifact flow: download -> scan -> cache -> serve

**Optional but valuable:**
- Database migration changes (audit log integrity)
- Configuration changes (new settings that affect security behavior)
- Dependency updates (supply chain risk)

## How to Dispatch

**1. Identify changed security-critical files:**
```bash
git diff --name-only origin/main...HEAD | grep -E '(scanner|cache|adapter|policy|api|bridge|scheduler)'
```

**2. Dispatch security-reviewer agent:**

Use the Agent tool with `security-reviewer` subagent type. Provide:
- What was changed and why
- Which security-critical paths are affected
- The git diff range (BASE_SHA..HEAD_SHA)
- Any specific security concerns you have

**3. Act on findings by severity:**

| Severity | Action |
|----------|--------|
| CRITICAL | Stop. Fix immediately. Re-review before proceeding. |
| HIGH | Fix before merge. No exceptions. |
| MEDIUM | Fix if straightforward; otherwise create tracked issue. |
| LOW | Note for future hardening. OK to merge without fixing. |

## Integration with cf-powers Workflow

**During `/analyse`:**
- Security review runs alongside BA and Dev reviews
- Invoke `review-as-security` skill on the analysis document

**During implementation (subagent-driven or batch):**
- After implementing scanner, cache, adapter, or policy tasks
- Use this skill to dispatch security-focused code review
- In addition to (not replacing) the standard code-reviewer

**Before merge:**
- If any security-critical paths were touched, dispatch security review
- Both code-reviewer AND security-reviewer should approve

## Red Flags

**Never:**
- Skip security review because "it's a small change" to a security-critical path
- Merge with unresolved CRITICAL or HIGH findings
- Dismiss findings without technical counter-evidence
- Assume scanner fail-open behavior is always safe

**If reviewer is wrong:**
- Push back with specific code references and threat model reasoning
- Explain why the identified attack vector is not exploitable in this context
- Document the security assumption for future reference
