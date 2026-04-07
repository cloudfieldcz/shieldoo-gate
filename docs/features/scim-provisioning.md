# SCIM User & Group Provisioning

> Automatic user and group synchronization from identity providers via the SCIM 2.0 protocol.

**Status:** Planned (v1.2+)

## Problem

With [RBAC](rbac.md) in place, user and role management becomes an operational concern. In enterprise environments, identity and access are managed centrally in an IdP (Entra ID, Okta, Google Workspace, etc.). Manually assigning roles in Shieldoo Gate creates drift, stale accounts, and compliance gaps.

SCIM (System for Cross-domain Identity Management) is the industry standard for automated user provisioning — IdPs push user/group changes to downstream applications in real time.

## Proposed Solution

Implement a SCIM 2.0 server endpoint in Shieldoo Gate that receives provisioning events from the IdP and automatically manages user accounts and role assignments.

### Key Requirements

1. **SCIM 2.0 endpoints** (RFC 7643 / 7644):
   ```
   GET    /scim/v2/Users                    — list users
   GET    /scim/v2/Users/{id}               — get user
   POST   /scim/v2/Users                    — create user
   PUT    /scim/v2/Users/{id}               — replace user
   PATCH  /scim/v2/Users/{id}               — partial update (enable/disable)
   DELETE /scim/v2/Users/{id}               — deprovision user
   
   GET    /scim/v2/Groups                   — list groups
   GET    /scim/v2/Groups/{id}              — get group
   POST   /scim/v2/Groups                   — create group
   PUT    /scim/v2/Groups/{id}              — replace group (membership)
   PATCH  /scim/v2/Groups/{id}              — add/remove members
   DELETE /scim/v2/Groups/{id}              — delete group
   
   GET    /scim/v2/ServiceProviderConfig     — capabilities discovery
   GET    /scim/v2/Schemas                   — schema discovery
   GET    /scim/v2/ResourceTypes             — resource type discovery
   ```

2. **User schema:**
   ```json
   {
     "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
     "id": "uuid",
     "userName": "user@example.com",
     "name": { "givenName": "...", "familyName": "..." },
     "emails": [{ "value": "user@example.com", "primary": true }],
     "active": true,
     "groups": [{ "value": "group-uuid", "display": "security-team" }]
   }
   ```

3. **Group-to-role mapping:** IdP groups map to Shieldoo Gate roles via configuration:
   ```yaml
   auth:
     scim:
       enabled: false
       bearer_token_env: "SGW_SCIM_TOKEN"     # Bearer token for SCIM endpoint auth
       group_role_mapping:
         "Security Team": "operator"
         "Security Leads": "policy-approver"
         "Platform Admins": "admin"
       default_role: "viewer"                  # Users in no mapped group
       deprovision_action: "disable"           # "disable" or "delete"
   ```

4. **Authentication:** SCIM endpoints are authenticated via a long-lived bearer token (standard for SCIM). The token is stored as an environment variable, never in config.

5. **Supported IdPs:**
   - **Microsoft Entra ID** (Azure AD) — native SCIM client, most common in enterprise
   - **Okta** — native SCIM provisioning
   - **Google Workspace** — via SCIM connector
   - **OneLogin, JumpCloud, etc.** — any SCIM 2.0 compliant IdP

### How It Fits Into the Architecture

- **New package:** `internal/scim/` — SCIM 2.0 server implementation
- **Database:** Extend `user_roles` table (from [RBAC](rbac.md)) with SCIM-specific fields:
  ```sql
  ALTER TABLE user_roles ADD COLUMN scim_id TEXT UNIQUE;
  ALTER TABLE user_roles ADD COLUMN display_name TEXT DEFAULT '';
  ALTER TABLE user_roles ADD COLUMN active BOOLEAN DEFAULT TRUE;
  ALTER TABLE user_roles ADD COLUMN provisioned_at DATETIME;
  ALTER TABLE user_roles ADD COLUMN deprovisioned_at DATETIME;
  ```
  New `scim_groups` table:
  ```sql
  CREATE TABLE scim_groups (
      id          TEXT PRIMARY KEY,    -- SCIM group UUID
      display_name TEXT NOT NULL,
      mapped_role  TEXT NOT NULL DEFAULT 'viewer',
      created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE scim_group_members (
      group_id    TEXT NOT NULL REFERENCES scim_groups(id),
      user_email  TEXT NOT NULL REFERENCES user_roles(email),
      PRIMARY KEY (group_id, user_email)
  );
  ```
- **Admin API server:** Mount SCIM routes on the admin port under `/scim/v2/`
- **RBAC integration:** When a user's group membership changes via SCIM, their role is automatically recalculated (highest role from all mapped groups, or `default_role` if no groups match)

### Provisioning Flow

```
IdP (Entra ID / Okta / Google)
    │
    │  SCIM 2.0 PUSH
    ▼
Shieldoo Gate /scim/v2/
    │
    ├── POST /Users → create user_roles row (role = default_role)
    ├── PATCH /Groups → update group membership → recalculate role
    ├── PATCH /Users (active=false) → disable user, revoke API keys
    └── DELETE /Users → disable or delete based on deprovision_action
```

### RBAC Synergy

| SCIM Event | RBAC Effect | Audit Event |
|---|---|---|
| User created | New `viewer` account | `USER_PROVISIONED` |
| User added to "Security Team" group | Role upgraded to `operator` | `ROLE_CHANGED` |
| User removed from all groups | Role downgraded to `viewer` | `ROLE_CHANGED` |
| User deactivated | Account disabled, API keys revoked | `USER_DEPROVISIONED` |
| Group deleted | All members lose that group's role contribution | `ROLE_CHANGED` (per member) |

### SIEM Integration

SCIM provisioning events are important for compliance monitoring:

- `USER_PROVISIONED` / `USER_DEPROVISIONED` — track account lifecycle
- `ROLE_CHANGED` with `source: "scim"` — distinguish automated role changes from manual
- `SCIM_AUTH_FAILED` — failed SCIM bearer token (potential misconfiguration or attack)

The [SIEM integration](siem-integration.md) feature should include these in its schema.

## Considerations

- **SCIM before RBAC:** SCIM provisioning only makes sense when RBAC is implemented. SCIM provides the "who is in which group" data, RBAC provides the "what can each role do" enforcement.
- **Conflict resolution:** When both OIDC claims and SCIM provide role information, SCIM should take precedence (it's the more authoritative source since it's pushed by the IdP).
- **Soft delete vs hard delete:** Enterprise IdPs typically expect "disable" (set `active=false`) rather than hard delete. The `deprovision_action` config controls this.
- **Rate limiting:** IdP initial provisioning can send hundreds of requests during first sync. The SCIM endpoint should handle bursts gracefully.
- **Testing:** Entra ID and Okta have SCIM test tools that validate endpoint compliance. Add E2E tests using these validators.
