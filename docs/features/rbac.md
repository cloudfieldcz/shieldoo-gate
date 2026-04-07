# Role-Based Access Control (RBAC)

> Fine-grained authorization with predefined roles controlling who can view, operate, and approve policy changes.

**Status:** Planned (v1.2+)

## Problem

Currently, Shieldoo Gate has a binary access model: either the admin API is open (no auth) or it is protected by OIDC (all authenticated users have full access). In real-world deployments, different people need different levels of access:

- **Developers** need to see what's cached, check scan results, and understand why a package was blocked — but should not be able to release quarantined artifacts or modify policy.
- **Security engineers** need full visibility and the ability to quarantine/release artifacts, manage overrides, and trigger rescans — but policy-level changes (like switching from strict to permissive mode) should require elevated approval.
- **Policy approvers** (security leads, compliance officers) need to approve or reject policy changes, manage allowlists, and configure policy tiers — with audit trail.
- **Admins** need full system access including user management, OIDC config, and alert configuration.

## Proposed Roles

| Role | Description | Typical User |
|---|---|---|
| **viewer** | Read-only access to all dashboards, artifacts, scan results, audit log | Developers, SREs, curious stakeholders |
| **operator** | Viewer + quarantine/release artifacts, trigger rescans, create temporary overrides | Security engineers, on-call responders |
| **policy-approver** | Operator + manage permanent overrides, change policy mode, edit allowlists, approve/reject policy change requests | Security leads, compliance officers |
| **admin** | Full access including user/role management, system configuration, alert settings | Platform team, security team leads |

### Permission Matrix

| Action | viewer | operator | policy-approver | admin |
|---|---|---|---|---|
| View artifacts, scan results, audit log | x | x | x | x |
| View dashboard and statistics | x | x | x | x |
| Download SBOMs (future) | x | x | x | x |
| Trigger manual rescan | | x | x | x |
| Quarantine artifact | | x | x | x |
| Release artifact from quarantine | | x | x | x |
| Create temporary override (with expiry) | | x | x | x |
| Create permanent override (no expiry) | | | x | x |
| Revoke overrides | | x (own only) | x | x |
| Change policy mode (strict/balanced/permissive) | | | x | x |
| Edit static allowlist | | | x | x |
| Configure AI triage settings | | | x | x |
| Manage API keys (own) | x | x | x | x |
| Manage API keys (all users) | | | | x |
| Configure alerts | | | | x |
| Manage users and roles | | | | x |
| View/edit system configuration | | | | x |

## Key Design Decisions

### Role Assignment

Roles can be assigned through two mechanisms:

1. **OIDC claims mapping:** Map OIDC groups/roles to Shieldoo Gate roles via configuration:
   ```yaml
   auth:
     rbac:
       enabled: true
       default_role: "viewer"           # Role for authenticated users with no explicit mapping
       claim: "groups"                   # OIDC claim to read roles from
       mapping:
         "security-team": "operator"
         "security-leads": "policy-approver"
         "platform-admins": "admin"
   ```

2. **Local role assignments:** For environments without OIDC group claims, admins can assign roles directly via the admin API:
   - `PUT /api/v1/users/{email}/role` — assign a role to a user
   - `GET /api/v1/users` — list users and their roles

### Database Schema

```sql
CREATE TABLE user_roles (
    email       TEXT PRIMARY KEY,
    role        TEXT NOT NULL DEFAULT 'viewer',
    assigned_by TEXT NOT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source      TEXT NOT NULL DEFAULT 'local'  -- 'local' or 'oidc'
);
```

OIDC-sourced roles are refreshed on every login. Local assignments take precedence over OIDC mappings (explicit override).

### Policy Change Approval Workflow

For sensitive policy changes (mode switch, allowlist edits), an optional approval workflow:

1. Operator or policy-approver proposes a change
2. Change is stored as `PENDING` in a `policy_changes` table
3. A different policy-approver (not the proposer) must approve
4. On approval, the change takes effect immediately
5. All steps are logged in the audit log with `POLICY_CHANGE_PROPOSED`, `POLICY_CHANGE_APPROVED`, `POLICY_CHANGE_REJECTED` events

This workflow is optional — when `rbac.require_approval: false`, policy-approvers can make changes directly.

### Proxy Endpoint Authorization

API key authentication for proxy endpoints (PAT) inherits the role of the key owner. This enables:

- **Audit trail enrichment:** Log entries show which user (via their PAT) downloaded a package
- **Per-role download policies (future):** E.g., "viewers can only download CLEAN artifacts, operators can download SUSPICIOUS ones"

## How It Fits Into the Architecture

- **Auth middleware:** Extend `internal/auth/` with role extraction from OIDC claims and a `RequireRole(role)` middleware for API endpoints.
- **Database:** New `user_roles` table (migration 014+). Optional `policy_changes` table for approval workflow.
- **Admin API:** Add role checks to existing handlers. New user management endpoints.
- **Admin UI:** Role-aware UI that hides/disables actions the user cannot perform. User management page for admins.
- **Audit log:** All role-restricted actions log the user's email and role.

## Relationship to SIEM Integration

RBAC events are high-value signals for SIEM platforms:

- `ROLE_ASSIGNED` / `ROLE_CHANGED` — track privilege changes
- `POLICY_CHANGE_PROPOSED` / `APPROVED` / `REJECTED` — compliance audit trail
- `UNAUTHORIZED_ACCESS_ATTEMPT` — failed authorization (someone tried an action above their role)
- `OVERRIDE_CREATED` with `created_by` role context — distinguish operator temporary overrides from policy-approver permanent ones

The [SIEM integration](siem-integration.md) feature should include these RBAC events in its schema mapping.

## Considerations

- **Backward compatibility:** When RBAC is disabled (`rbac.enabled: false`), all authenticated users have `admin` role (current behavior). RBAC is opt-in.
- **Bootstrap problem:** The first user to log in (or a user specified in config `rbac.initial_admin`) gets the `admin` role automatically.
- **Emergency bypass:** An environment variable (`SGW_RBAC_EMERGENCY_ADMIN_EMAIL`) can grant admin access to a specific email, bypassing OIDC group mapping. Useful when the OIDC provider is misconfigured.
- **Granularity:** The four predefined roles cover the most common access patterns. Custom roles with per-endpoint permissions could be added later but add significant complexity — start with fixed roles.
