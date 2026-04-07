# Planned Features

> Feature proposals for future Shieldoo Gate releases. Each feature has a dedicated document with problem statement, proposed solution, architecture impact, and considerations.

## Feature Overview

| Feature | Description | Dependencies | Priority |
|---|---|---|---|
| [RBAC](rbac.md) | Role-based access control with four predefined roles (viewer, operator, policy-approver, admin) to enforce least-privilege access to the admin API and policy management | OIDC auth (done) | High |
| [SCIM Provisioning](scim-provisioning.md) | Automated user and group synchronization from identity providers (Entra ID, Okta, Google) via SCIM 2.0 protocol | RBAC | High |
| [SBOM Generation](sbom-generation.md) | Automatic Software Bill of Materials generation for every cached artifact in CycloneDX and SPDX formats, accessible via API and UI | Trivy (done) | Medium |
| [License Policy](license-policy.md) | Block, quarantine, or warn on artifacts containing licenses incompatible with organizational policy (GPL, AGPL, etc.) | SBOM Generation (recommended) | Medium |
| [Dependency Graph](dependency-graph.md) | Visual dependency graph with impact analysis — when a package is quarantined, show blast radius across all downstream consumers | SBOM Generation (recommended) | Medium |
| [SIEM Integration](siem-integration.md) | Native integration with Splunk (HEC), Elastic (ECS), Microsoft Sentinel, and Syslog (CEF) for centralized security monitoring | Alerting (done), RBAC (recommended) | Medium |
| [Threat Feed Contributions](threat-feed-contributions.md) | Community portal for submitting, reviewing, and publishing malicious package reports to the shared threat feed | Threat Feed (done) | Low |

## Dependency Graph

```
OIDC Auth (done)
    │
    ▼
  RBAC ──────────────▶ SCIM Provisioning
    │
    ▼
  SIEM Integration
                    
Trivy (done)
    │
    ▼
  SBOM Generation
    │
    ├──▶ License Policy
    │
    └──▶ Dependency Graph

Threat Feed (done)
    │
    ▼
  Threat Feed Contributions (separate service)
```

## Implementation Notes

- Features are listed in suggested implementation order within each dependency chain
- "High" priority features (RBAC, SCIM) are prerequisites for enterprise adoption
- "Medium" priority features (SBOM, License, Dependency Graph, SIEM) add significant value for compliance and visibility
- "Low" priority features (Threat Feed Portal) are community-oriented and can be a separate project
- All features should follow existing patterns: structured JSON logging, audit trail, Prometheus metrics, fail-open where applicable
