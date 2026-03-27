---
name: review-as-security
description: Use when reviewing a technical analysis, design document, or specification from a security perspective - checking supply chain attack vectors, trust boundaries, artifact integrity, scanner bypass risks, and security invariant compliance
---

# Review as Security Engineer

## Overview

Review a technical analysis or specification from a security engineer perspective. Focus on supply chain attack vectors, trust boundary violations, artifact integrity gaps, and compliance with the project's five security invariants.

**Announce at start:** "I'm reviewing this document as a Security Engineer."

## Input

- Design + analysis document (typically `docs/plans/YYYY-MM-DD-<topic>.md`)
- The actual codebase (read relevant files to verify security claims)
- CLAUDE.md security invariants section (always reference)

## Review Checklist

### 1. Security Invariant Compliance (DO THIS FIRST)

**CRITICAL:** Verify every proposed change against the five invariants in CLAUDE.md:
1. Never serve a quarantined artifact
2. Never trust artifact content before scan completes
3. Never log secrets
4. Never unpin scanner dependencies
5. Audit log is append-only

Read the actual code paths affected by the proposed changes.

### 2. Supply Chain Attack Vectors

- Can the proposed change introduce cache poisoning?
- Are there TOCTOU windows between scan and serve?
- Can scanning be bypassed via edge cases (partial downloads, encoding tricks)?
- Is hash verification end-to-end (download -> scan -> cache -> serve)?
- Can upstream responses be manipulated (redirects, DNS rebinding)?

### 3. Trust Boundary Validation

- Are all trust boundaries identified in the analysis?
- Is input validation sufficient at each boundary?
- Is untrusted data (artifact content, upstream headers) sanitized before use?
- Is the gRPC channel between Go and Python bridge secured?
- Are scanner results validated before acting on them?

### 4. Authentication and Secrets

- Are upstream credentials handled securely?
- Are API keys/tokens properly scoped and rotated?
- Is the admin UI protected (CSRF, XSS, session management)?
- Are secrets excluded from logs and error messages?

### 5. Denial of Service Resilience

- Are there size limits on artifacts (zip bombs, tar bombs)?
- Are there timeouts on all external calls?
- Is there circuit-breaking for scanner failures?
- Can an attacker exhaust cache storage?

### 6. Fail-Safe Design

- Is the fail-open/fail-closed behavior appropriate for each path?
- What happens when external dependencies are unreachable?
- Are error paths tested and secure?

## Output Format

Structure your review exactly like this:

```markdown
# Security Review: <topic>

## Summary
[1-2 sentence security posture assessment]

## Security Invariants
- ✅ [Invariant maintained — cite evidence]
- CRITICAL: [Invariant violated — cite code, describe attack]

## Attack Surface
- HIGH: [Attack vector — scenario, impact, remediation]
- MEDIUM: [Defense-in-depth gap]

## Trust Boundaries
- ✅ [Proper validation at boundary]
- HIGH: [Insufficient validation — risk description]

## Cryptography and Integrity
- ✅ [Correct integrity check]
- MEDIUM: [Missing or weak check]

## Fail-Safe Behavior
- ✅ [Correct fail-safe]
- MEDIUM: [Missing protection]

## Security Questions
1. [Question about security design decision]

## Recommendations
1. [Actionable security recommendation — priority order]

## Verdict
**Security Posture:** [Solid / Needs Improvement / Critical Deficiencies]
**Recommended Action:** [Proceed / Address Feedback / Requires Security Redesign]
```

## Key Principles

- **Verify against code** — Always read the actual files; don't trust the analysis claims
- **Think like an attacker** — For each component, ask "how would I abuse this?"
- **Specific attack scenarios** — Don't say "could be vulnerable"; describe the exact attack path
- **Prioritize by exploitability** — Real risks over theoretical concerns
- **Defense in depth** — One control failing shouldn't compromise the system
- **Project invariants are sacred** — Any violation is automatically CRITICAL
