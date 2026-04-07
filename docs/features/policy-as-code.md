# Policy-as-Code (OPA / Rego)

> Define and version-control supply chain security policies using Open Policy Agent (OPA) and Rego, enabling testable, auditable, and GitOps-compatible policy management.

**Status:** Proposed
**Priority:** Medium
**Perspective:** DevSecOps / Platform Engineering

## Problem

Shieldoo Gate's current policy engine uses a fixed evaluation order (overrides → allowlist → verdict thresholds) with three configurable modes (strict, balanced, permissive). This covers common use cases, but organizations with complex requirements face limitations:

- **No conditional logic:** Cannot express rules like "block SUSPICIOUS for production registries but allow for dev environments" or "quarantine packages from new maintainers only if they have install hooks."
- **No version control:** Policy changes via the Admin UI are effective immediately with no review process (beyond the planned RBAC approval workflow). There is no way to test a policy change before deploying it.
- **No composability:** Cannot combine organizational policies with team-specific overrides in a structured way.
- **No external data:** Cannot enrich policy decisions with data from external systems (internal package registry, HR system for maintainer verification, CMDB for environment classification).

## Proposed Solution

Integrate Open Policy Agent (OPA) as an optional policy evaluation backend, allowing organizations to define policies in Rego (OPA's declarative policy language) and manage them via Git.

### Architecture

```
Scan Results + Artifact Metadata
        │
        ▼
  ┌─────────────┐
  │ Policy Engine│
  │   (Go)      │
  │             │
  │  ┌─────────┐│     ┌──────────────┐
  │  │Built-in ││     │ OPA (embedded)│
  │  │Rules    ││     │              │
  │  │(default)││ OR  │ Rego policies│
  │  └─────────┘│     │ from config/ │
  │             │     │ git repo     │
  │             │     └──────────────┘
  └──────┬──────┘
         │
         ▼
  Policy Decision (ALLOW / BLOCK / QUARANTINE / WARN)
```

### Policy Examples

```rego
# policy/supply_chain.rego

package shieldoo.policy

import future.keywords.if
import future.keywords.in

default decision = "ALLOW"

# Block anything with MALICIOUS verdict
decision = "BLOCK" if {
    some result in input.scan_results
    result.verdict == "MALICIOUS"
    result.confidence >= 0.7
}

# Quarantine new packages (< 30 days old) with SUSPICIOUS verdict
decision = "QUARANTINE" if {
    some result in input.scan_results
    result.verdict == "SUSPICIOUS"
    input.artifact.first_seen_upstream < time.now_ns() - (30 * 24 * 60 * 60 * 1000000000)
}

# Allow SUSPICIOUS findings for allowlisted packages
decision = "ALLOW" if {
    input.artifact.ecosystem_name in data.allowlist
}

# Block packages from recently transferred maintainers
decision = "QUARANTINE" if {
    input.artifact.maintainer_changed_recently == true
    some result in input.scan_results
    result.verdict == "SUSPICIOUS"
}
```

### Key Requirements

1. **Embedded OPA:** Use the OPA Go SDK (`github.com/open-policy-agent/opa/rego`) to evaluate policies in-process. No external OPA server needed (but optionally supported).
2. **Policy loading:** Policies loaded from local directory (`policy/`), Git repository (cloned on startup + periodic pull), or OPA bundle server.
3. **Input schema:** Define a stable input document schema that includes artifact metadata, scan results, findings, cache status, request context (client IP, user agent), and time.
4. **Fallback:** If OPA evaluation fails, fall back to the built-in policy engine. Never block all traffic due to a policy error.
5. **Testing:** Ship `opa test` integration so policy authors can write unit tests for their Rego policies. Provide example test fixtures.
6. **Dry-run mode:** Evaluate OPA policies in parallel with built-in rules, log the OPA decision, but use the built-in decision. Allows organizations to validate OPA policies before switching over.
7. **Decision logging:** Log every OPA decision (input hash, policy version, decision, evaluation time) for audit compliance.

### Configuration

```yaml
policy:
  engine: "builtin"                   # "builtin" | "opa" | "opa-dry-run"
  opa:
    policy_path: "./policy/"          # Local directory with .rego files
    git:
      enabled: false
      url: "https://github.com/myorg/shieldoo-policies.git"
      branch: "main"
      pull_interval: "5m"
      ssh_key_env: "SGW_POLICY_GIT_KEY"
    bundle:
      enabled: false
      url: ""                         # OPA bundle server URL
      polling_interval: "30s"
    decision_log:
      enabled: true
      console: false                  # Log decisions to stdout
    external_data:                    # Additional data sources for Rego policies
      - name: "internal_registry"
        url: "https://internal-registry.example.com/api/packages"
        refresh_interval: "1h"
```

### How It Fits Into the Architecture

- **Policy Engine:** Add `OPAEvaluator` as an alternative to the existing `BuiltinEvaluator` in `internal/policy/`. Both implement the same `PolicyEvaluator` interface.
- **Dependencies:** `github.com/open-policy-agent/opa` (Go SDK for embedded evaluation).
- **Database:** Decision log entries stored in a new `opa_decisions` table or appended to the existing audit log.
- **Admin UI:** Show current policy engine mode, loaded policy files, last sync status (if Git-based), and recent decision log entries.

### Considerations

- **Learning curve:** Rego has a learning curve. Provide comprehensive example policies and a getting-started guide. Most organizations can start with the built-in engine and graduate to OPA as needs grow.
- **Performance:** Embedded OPA evaluation adds ~1–5ms per decision. Pre-compile Rego policies at startup to minimize runtime overhead.
- **Policy conflicts:** When migrating from built-in to OPA, ensure the OPA policies replicate the built-in behavior. The dry-run mode helps catch discrepancies.
- **Compliance:** OPA decision logs provide a complete audit trail of every policy decision, which strengthens compliance posture.
