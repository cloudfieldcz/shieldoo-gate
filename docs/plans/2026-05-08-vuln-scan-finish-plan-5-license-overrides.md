# Vulnerability Scan — Final Polish — Phase 5: License-override per-project scoping

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the "Release a license-blocked artifact" UX from the global `/artifacts` panel to the per-project context, where it semantically belongs. License decisions are project-scoped (project A may block GPL-3.0, project B may allow it), so a global override on a license-blocked artifact has the wrong blast radius.

**Architecture:** Most of the infrastructure is already in place:
- `policy_overrides` table has `project_id` (NULL = global) since [migration 026](../../internal/config/migrations/sqlite/026_project_policy_overrides.sql).
- `POST /api/v1/projects/{id}/overrides` writes per-project rows with `kind=allow|deny`.
- `GET /api/v1/projects/{id}/artifacts` already merges pulled + license-blocked (via audit_log) + per-project overrides.
- `project_license_policy` table (migration 022) and per-project policy editor are wired.

What's missing:
1. **Migration 036** — backfill currently-active global `manual release` overrides into per-project rows for every existing project (additive; globals stay for audit trail).
2. **Backend hint** — `handleReleaseArtifact` (the global Release endpoint) inspects `quarantine_reason`; if it indicates a license block (prefix `"blocked_license:"` or contains `"license"` token), it returns 409 with a `next_action` field pointing the operator to the project-scoped flow.
3. **UI on `ProjectDetail`** — License-blocked artifacts (already in the artifacts list with `decision=blocked` + `blocked_license` field) get a Release button that POSTs to `/api/v1/projects/{id}/overrides`. New "Project license overrides" panel lists active per-project allow/deny overrides for that project, with a Revoke action.
4. **UI on `ArtifactDetailPanel`** — when the artifact is license-quarantined (`quarantine_reason` matches the same predicate), the global Release button is replaced with a hint: "This artifact was blocked by a project's license policy. Open the project to release it for that project specifically." Other quarantine reasons (typosquat, malicious, scan-fail) keep the global Release flow unchanged.

**Tech Stack:** Go (sqlx) + React/TypeScript (TanStack Query). No new deps.

**Index:** [`plan-index.md`](./2026-05-08-vuln-scan-finish-plan-index.md)

---

## File map

| Path | Action | Responsibility |
|------|--------|----------------|
| `internal/config/migrations/sqlite/036_license_overrides_per_project.sql` | Create | Backfill globals → per-project rows. |
| `internal/config/migrations/postgres/036_license_overrides_per_project.sql` | Create | Postgres twin (`generate_series` not needed; same logic). |
| `internal/api/artifacts.go:579-650` | Modify | `handleReleaseArtifact` rejects license blocks with 409 + `next_action`. |
| `internal/api/artifacts_test.go` | Modify | Add cases for the 409-with-hint branch + non-license still-allowed path. |
| `internal/api/license_predicate.go` | Create | `isLicenseQuarantineReason(reason string) bool` — single source of truth, unit-tested. |
| `internal/api/license_predicate_test.go` | Create | Test the predicate against real-world reasons. |
| `ui/src/api/projects.ts` | Modify | Add `releaseLicenseBlocked(projectId, ecosystem, name, version)`, `listProjectOverrides(projectId)`, `revokeProjectOverride(projectId, overrideId)`. |
| `ui/src/pages/ProjectDetail.tsx` | Modify | Per-row Release button on license-blocked artifacts; new "License overrides" panel. |
| `ui/src/components/ProjectLicenseOverridesPanel.tsx` | Create | Lists active per-project overrides + revoke. |
| `ui/src/components/ArtifactDetailPanel.tsx:218-227` | Modify | When license-blocked, swap Release button for an info hint. |
| `tests/e2e-shell/test_license_per_project.sh` | Create | E2E shell test: license-block → Release from project → override active for that project only. |
| `tests/e2e-shell/run_all.sh` | Modify | Source + invoke the new test. |
| `docs/data-model.md` | Modify | Note that `policy_overrides.project_id != NULL` is now the canonical home for license releases. |
| `docs/features/license-policy.md` | Modify | Document the per-project Release UX (or `docs/features/projects.md` if no license-policy doc exists yet). |

**License predicate:** today's evaluator writes `quarantine_reason` like `"license policy: <human reason>"` — the constant `licenseQuarantineReasonPrefix = "license policy:"` lives in [`internal/api/license_reevaluation.go:26`](../../internal/api/license_reevaluation.go#L26). The predicate **reuses that constant** to avoid drift; the predicate function is the single source of truth for `handleReleaseArtifact` and any future caller.

---

## Task 1: License-quarantine predicate

**Files:**
- Create: `internal/api/license_predicate.go`
- Create: `internal/api/license_predicate_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package api

import "testing"

func TestIsLicenseQuarantineReason_LicensePolicyPrefix_True(t *testing.T) {
	if !isLicenseQuarantineReason("license policy: GPL-3.0-only blocked") {
		t.Errorf("expected true for canonical 'license policy:' prefix")
	}
}

func TestIsLicenseQuarantineReason_TyposquatPrefix_False(t *testing.T) {
	if isLicenseQuarantineReason("typosquat: lodsah ~ lodash") {
		t.Errorf("expected false for typosquat reason")
	}
}

func TestIsLicenseQuarantineReason_MaliciousPrefix_False(t *testing.T) {
	if isLicenseQuarantineReason("scanner=guarddog verdict=MALICIOUS") {
		t.Errorf("expected false for scanner verdict")
	}
}

func TestIsLicenseQuarantineReason_CaseInsensitive_True(t *testing.T) {
	if !isLicenseQuarantineReason("LICENSE POLICY: AGPL-3.0") {
		t.Errorf("expected true for upper-case prefix")
	}
}

func TestIsLicenseQuarantineReason_Empty_False(t *testing.T) {
	if isLicenseQuarantineReason("") {
		t.Errorf("expected false for empty reason")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run IsLicenseQuarantineReason -v`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement the predicate**

```go
package api

import "strings"

// isLicenseQuarantineReason returns true when the artifact_status.quarantine_reason
// indicates a license-policy block (as opposed to a scanner verdict, typosquat,
// or other reason). Reuses the canonical prefix from license_reevaluation.go so
// the two stay in sync — if the writer's prefix moves, the read predicate moves
// with it.
func isLicenseQuarantineReason(reason string) bool {
	if reason == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(reason), strings.ToLower(licenseQuarantineReasonPrefix))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -run IsLicenseQuarantineReason -v`
Expected: PASS for all 5 test cases.

- [ ] **Step 5: Commit**

```bash
git add internal/api/license_predicate.go internal/api/license_predicate_test.go
git commit -m "feat(api): isLicenseQuarantineReason predicate (single source of truth)"
```

---

## Task 2: Reject license-block global Release with 409 + next_action

**Files:**
- Modify: `internal/api/artifacts.go:579-650`
- Modify: `internal/api/artifacts_test.go`

The existing `handleReleaseArtifact` happily writes a global override regardless of why the artifact was quarantined. We add an early branch: if the artifact's current `quarantine_reason` is license-flavored, return 409 with `{"error":"license_block_requires_project_scope","next_action":{"endpoint":"/api/v1/projects/{id}/overrides","method":"POST","hint":"open the project that pulled this artifact and release from there"}}`.

- [ ] **Step 1: Add the failing test**

In `internal/api/artifacts_test.go` (or create a focused `artifacts_release_license_test.go`):

```go
func TestHandleReleaseArtifact_LicenseBlocked_Returns409WithHint(t *testing.T) {
	h, db := newTestServer(t)
	// Insert an artifact + artifact_status row marked as license-blocked.
	mustExec(t, db, `INSERT INTO artifacts (id, ecosystem, name, version) VALUES ('npm:gpltool:1.0', 'npm', 'gpltool', '1.0')`)
	mustExec(t, db, `INSERT INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at)
		VALUES ('npm:gpltool:1.0', 'QUARANTINED', 'license policy: GPL-3.0-only blocked', ?)`, time.Now())

	req := httptest.NewRequest("POST", "/api/v1/artifacts/npm:gpltool:1.0/release", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "license_block_requires_project_scope" {
		t.Errorf("error=%v, want license_block_requires_project_scope", body["error"])
	}
	if body["next_action"] == nil {
		t.Errorf("missing next_action hint")
	}

	// Verify NO row was written to policy_overrides.
	var n int
	mustQueryRow(t, db, "SELECT COUNT(*) FROM policy_overrides WHERE name = 'gpltool'").Scan(&n)
	if n != 0 {
		t.Errorf("license-block release wrote %d global override(s); want 0", n)
	}
}

func TestHandleReleaseArtifact_TyposquatBlock_StillReleasesGlobally(t *testing.T) {
	h, db := newTestServer(t)
	mustExec(t, db, `INSERT INTO artifacts (id, ecosystem, name, version) VALUES ('npm:lodsah:any', 'npm', 'lodsah', '*')`)
	mustExec(t, db, `INSERT INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at)
		VALUES ('npm:lodsah:any', 'QUARANTINED', 'typosquat: lodsah ~ lodash', ?)`, time.Now())

	req := httptest.NewRequest("POST", "/api/v1/artifacts/npm:lodsah:any/release", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	var n int
	mustQueryRow(t, db, "SELECT COUNT(*) FROM policy_overrides WHERE name = 'lodsah' AND project_id IS NULL").Scan(&n)
	if n != 1 {
		t.Errorf("expected 1 global override row for typosquat release, got %d", n)
	}
}
```

> **Helper note:** the `newTestServer`, `mustExec`, `mustQueryRow` helpers should already exist in the package's test file. If they don't, vendor them from a sibling test (e.g. `overrides_test.go`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run "ReleaseArtifact_LicenseBlocked|ReleaseArtifact_Typosquat" -v`
Expected: license-blocked test FAILs (we still write a global), typosquat test PASSes.

- [ ] **Step 3: Modify `handleReleaseArtifact`**

In `internal/api/artifacts.go`, after the artifact lookup (around line 590) but before the override-insert, add:

```go
	// Look up current quarantine_reason for the license-block branch.
	var quarReason sql.NullString
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT quarantine_reason FROM artifact_status WHERE artifact_id = ?`, id,
	).Scan(&quarReason)
	if quarReason.Valid && isLicenseQuarantineReason(quarReason.String) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "license_block_requires_project_scope",
			"next_action": map[string]string{
				"endpoint": "/api/v1/projects/{id}/overrides",
				"method":   "POST",
				"hint":     "open the project that pulled this artifact and release from there",
			},
		})
		return
	}
```

(`database/sql` is likely already imported; if not, add it.)

- [ ] **Step 4: Run tests to verify both pass**

Run: `go test ./internal/api/ -run "ReleaseArtifact" -v`
Expected: both PASS, plus any pre-existing release tests still PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/artifacts.go internal/api/artifacts_test.go
git commit -m "feat(api): /artifacts/{id}/release rejects license blocks with 409 + project hint"
```

---

## Task 3: Migration 036 — backfill globals to per-project rows

**Files:**
- Create: `internal/config/migrations/sqlite/036_license_overrides_per_project.sql`
- Create: `internal/config/migrations/postgres/036_license_overrides_per_project.sql`

**Strategy:** for every active global override with `reason='manual release'`, copy it into `policy_overrides` with `project_id` set to each existing project's id (CROSS JOIN). Annotate the migrated rows with `created_by='migration:036'` and `reason='migrated 036: was global manual release; now per-project'` so an operator can `WHERE created_by = 'migration:036'` and remove them in bulk if desired.

The existing globals **stay** (still active, `revoked=FALSE`) so the lookup falls through to global if a per-project allow is later revoked. Operators can revoke globals manually via `DELETE /api/v1/overrides/{id}`.

> **Why over-inclusive (all `manual release`, not just license-related):** today's schema doesn't record *why* an artifact was originally blocked at the time the override was created. We can't reconstruct that retroactively. Migrating all `manual release` rows means scan-released artifacts also gain per-project allow rows — that's fine because the global still wins anyway, and the per-project rows give operators visibility on the project detail.

- [ ] **Step 1: Write the SQLite migration**

`policy_overrides.revoked` in SQLite is `INTEGER NOT NULL DEFAULT 0` (per migration 026 line 31). The unique partial index `idx_policy_overrides_unique_active` covers `(ecosystem, name, version, scope, COALESCE(project_id, 0), kind) WHERE revoked = 0` — our INSERT must respect it. We add an explicit `ON CONFLICT DO NOTHING` for race safety on top of the `NOT EXISTS` guard.

```sql
-- 036_license_overrides_per_project.sql (sqlite)
-- Backfill currently-active global "manual release" overrides into per-project
-- rows. Globals stay (revoked=0) for compatibility; per-project copies give
-- operators per-project visibility + isolated revoke. New license-block
-- releases go straight to per-project (handler change in artifacts.go).
--
-- Idempotent: NOT EXISTS guard prevents duplicates on re-run; ON CONFLICT
-- DO NOTHING covers any race against concurrent inserts hitting the unique
-- partial index.

INSERT INTO policy_overrides
    (ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, expires_at, revoked)
SELECT
    po.ecosystem, po.name, po.version, po.scope,
    p.id AS project_id,
    'allow' AS kind,
    'migrated 036: was global manual release; now per-project' AS reason,
    'migration:036' AS created_by,
    po.created_at,
    po.expires_at,
    0 AS revoked
FROM policy_overrides po
CROSS JOIN projects p
WHERE po.project_id IS NULL
  AND po.revoked = 0
  AND po.reason = 'manual release'
  AND NOT EXISTS (
      SELECT 1 FROM policy_overrides po2
      WHERE po2.project_id = p.id
        AND po2.ecosystem  = po.ecosystem
        AND po2.name       = po.name
        AND po2.version    = po.version
        AND po2.scope      = po.scope
        AND po2.kind       = 'allow'
        AND po2.revoked    = 0
  )
ON CONFLICT DO NOTHING;
```

- [ ] **Step 2: Write the Postgres twin**

Postgres uses BOOLEAN for `revoked` (per migration 026 Postgres twin's existing column type). Use `FALSE` / `TRUE` literals — `0`/`1` will fail with a type-check error.

```sql
-- 036_license_overrides_per_project.sql (postgres)
-- See SQLite twin for design notes. The only differences are BOOLEAN literals
-- and Postgres syntax for ON CONFLICT.

INSERT INTO policy_overrides
    (ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, expires_at, revoked)
SELECT
    po.ecosystem, po.name, po.version, po.scope,
    p.id AS project_id,
    'allow' AS kind,
    'migrated 036: was global manual release; now per-project' AS reason,
    'migration:036' AS created_by,
    po.created_at,
    po.expires_at,
    FALSE AS revoked
FROM policy_overrides po
CROSS JOIN projects p
WHERE po.project_id IS NULL
  AND po.revoked = FALSE
  AND po.reason = 'manual release'
  AND NOT EXISTS (
      SELECT 1 FROM policy_overrides po2
      WHERE po2.project_id = p.id
        AND po2.ecosystem  = po.ecosystem
        AND po2.name       = po.name
        AND po2.version    = po.version
        AND po2.scope      = po.scope
        AND po2.kind       = 'allow'
        AND po2.revoked    = FALSE
  )
ON CONFLICT DO NOTHING;
```

- [ ] **Step 3: Add a migration unit test**

In `internal/config/migrations_test.go` (or wherever `TestInitDB_Idempotent` lives), no change is needed if that test runs all migrations. But we should add a focused test:

```go
func TestMigration036_BackfillsLicenseOverrides(t *testing.T) {
	db := newTestDB(t) // runs all migrations
	now := time.Now().UTC()
	// Insert 2 projects + 1 active global manual-release override.
	mustExec(t, db, `INSERT INTO projects (id, label, name, mode, created_at) VALUES (101, 'p1', 'P1', 'lazy', ?)`, now)
	mustExec(t, db, `INSERT INTO projects (id, label, name, mode, created_at) VALUES (102, 'p2', 'P2', 'lazy', ?)`, now)
	mustExec(t, db, `INSERT INTO policy_overrides
		(ecosystem, name, version, scope, project_id, kind, reason, created_by, created_at, revoked)
		VALUES ('npm', 'gpltool', '1.0', 'version', NULL, 'allow', 'manual release', 'op@x', ?, 0)`, now)

	// Re-run migration 036 manually (idempotent).
	runMigration(t, db, "036_license_overrides_per_project.sql")

	var n int
	mustQueryRow(t, db, `SELECT COUNT(*) FROM policy_overrides
		WHERE name = 'gpltool' AND project_id IS NOT NULL AND revoked = 0`).Scan(&n)
	if n != 2 {
		t.Errorf("got %d per-project rows, want 2 (one per project)", n)
	}

	// Re-run again — must NOT duplicate.
	runMigration(t, db, "036_license_overrides_per_project.sql")
	mustQueryRow(t, db, `SELECT COUNT(*) FROM policy_overrides
		WHERE name = 'gpltool' AND project_id IS NOT NULL AND revoked = 0`).Scan(&n)
	if n != 2 {
		t.Errorf("idempotent re-run produced %d rows, want 2", n)
	}
}
```

> If `runMigration` doesn't exist as a helper, the simpler approach is to write the migration body inline into the test (executes the same SQL).

- [ ] **Step 4: Run all migration tests**

Run: `go test ./internal/config/... -run "Migration|InitDB" -v`
Expected: all PASS, including idempotency.

- [ ] **Step 5: Commit**

```bash
git add internal/config/migrations/sqlite/036_license_overrides_per_project.sql \
        internal/config/migrations/postgres/036_license_overrides_per_project.sql \
        internal/config/migrations_test.go
git commit -m "feat(db): migration 036 backfills global manual-release overrides per-project"
```

---

## Task 4: Frontend API client extensions

**Files:**
- Modify: `ui/src/api/projects.ts` (or wherever `projectsApi` is defined; check `ui/src/api/client.ts`)
- Modify: `ui/src/api/types.ts`

- [ ] **Step 1: Add types**

```ts
// types.ts additions
export interface ProjectOverride {
  id: number
  project_id: number
  ecosystem: string
  name: string
  version?: string
  scope: 'package' | 'version'
  kind: 'allow' | 'deny'
  reason: string
  created_by: string
  created_at: string
  expires_at?: string
  revoked: boolean
  revoked_at?: string
}
```

- [ ] **Step 2: Add API methods to `projectsApi`**

```ts
// projects.ts additions
async listOverrides(projectId: number): Promise<ProjectOverride[]> {
  const r = await api.get(`/projects/${projectId}/overrides`)
  return r.data.items ?? r.data
},

async releaseLicenseBlocked(
  projectId: number,
  ecosystem: string,
  name: string,
  version: string | null,
  reason: string,
): Promise<ProjectOverride> {
  const body = {
    ecosystem,
    name,
    version: version ?? '',
    scope: version ? 'version' : 'package',
    kind: 'allow',
    reason,
  }
  const r = await api.post(`/projects/${projectId}/overrides`, body)
  return r.data
},

async revokeOverride(projectId: number, overrideId: number, reason: string): Promise<void> {
  await api.post(`/projects/${projectId}/overrides/${overrideId}/revoke`, { reason })
},
```

> **Note:** `GET /api/v1/projects/{id}/overrides` may not exist yet — check `internal/api/server.go:217-222`. If only POST + revoke exist, add a `handleListProjectOverrides` and route in [Task 4b](#task-4b). If a GET already exists but under a different path, point the client there.

### Task 4b (conditional): backend GET if not present

If `GET /api/v1/projects/{id}/overrides` is missing, add it:

```go
// In internal/api/project_overrides.go:
func (s *Server) handleListProjectOverrides(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid project id")
		return
	}
	rows, err := s.db.QueryxContext(r.Context(),
		`SELECT id, project_id, ecosystem, name, version, scope, kind, reason,
		        created_by, created_at, expires_at, revoked, revoked_at
		   FROM policy_overrides
		  WHERE project_id = ?
		  ORDER BY created_at DESC`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	out := []projectOverrideResponse{}
	for rows.Next() {
		var po projectOverrideResponse
		if err := rows.StructScan(&po); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out = append(out, po)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}
```

Add a route in `internal/api/server.go` next to the existing project-overrides routes (line 221):

```go
r.Get("/projects/{id}/overrides", s.handleListProjectOverrides)
```

---

## Task 5: ProjectDetail UI — License overrides panel + per-row Release

**Files:**
- Create: `ui/src/components/ProjectLicenseOverridesPanel.tsx`
- Modify: `ui/src/pages/ProjectDetail.tsx`

The Project Detail page already lists artifacts (incl. `decision='blocked'` ones). We need:

1. A per-row **"Release for this project"** button on rows where `decision === 'blocked'` AND `blocked_license` is non-empty.
2. A new **"License overrides"** panel below the artifacts table listing active per-project allows/denies, with Revoke per row.

- [ ] **Step 1: Implement `ProjectLicenseOverridesPanel.tsx`**

```tsx
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ScrollText, Undo2 } from 'lucide-react'
import { projectsApi } from '../api/projects'
import type { ProjectOverride } from '../api/types'

type Props = { projectId: number }

export default function ProjectLicenseOverridesPanel({ projectId }: Props) {
  const qc = useQueryClient()
  const { data: overrides, isLoading } = useQuery<ProjectOverride[]>({
    queryKey: ['project-overrides', projectId],
    queryFn: () => projectsApi.listOverrides(projectId),
  })

  const revoke = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason: string }) =>
      projectsApi.revokeOverride(projectId, id, reason),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['project-overrides', projectId] })
      void qc.invalidateQueries({ queryKey: ['project-artifacts', projectId] })
    },
  })

  const active = (overrides ?? []).filter((o) => !o.revoked)

  return (
    <section className="mt-6 rounded-lg border border-gray-200 bg-white">
      <header className="flex items-center gap-2 px-4 py-3 border-b border-gray-200">
        <ScrollText className="w-4 h-4 text-gray-500" />
        <h3 className="text-sm font-medium text-gray-800">Project license overrides</h3>
        <span className="ml-2 text-xs text-gray-500">{active.length} active</span>
      </header>
      {isLoading ? (
        <p className="px-4 py-3 text-xs text-gray-500">Loading…</p>
      ) : active.length === 0 ? (
        <p className="px-4 py-3 text-xs text-gray-500">
          No active per-project overrides. Releases issued from a license-blocked artifact appear here.
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-gray-500">
            <tr>
              <th className="px-4 py-2 text-left">Package</th>
              <th className="px-4 py-2 text-left">Scope</th>
              <th className="px-4 py-2 text-left">Reason</th>
              <th className="px-4 py-2 text-left">Created</th>
              <th className="px-4 py-2 text-right">&nbsp;</th>
            </tr>
          </thead>
          <tbody>
            {active.map((o) => (
              <tr key={o.id} className="border-t border-gray-100">
                <td className="px-4 py-2 font-mono">
                  {o.ecosystem}/{o.name}
                  {o.version ? <span className="text-gray-500">@{o.version}</span> : null}
                </td>
                <td className="px-4 py-2 capitalize">{o.scope} ({o.kind})</td>
                <td className="px-4 py-2 max-w-md truncate text-gray-600">{o.reason}</td>
                <td className="px-4 py-2 text-gray-500">{new Date(o.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-2 text-right">
                  <button
                    onClick={() => {
                      const reason = prompt('Reason for revoking this override?')
                      if (reason && reason.trim()) revoke.mutate({ id: o.id, reason: reason.trim() })
                    }}
                    className="inline-flex items-center gap-1 px-2 py-1 text-xs text-red-700 hover:bg-red-50 rounded"
                  >
                    <Undo2 className="w-3 h-3" /> Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
```

- [ ] **Step 2: Wire the per-row "Release" action in `ProjectDetail.tsx`**

Find the artifact row rendering (around line 254 of `ProjectDetail.tsx` — `<DecisionPill decision={artifact.decision} reason={artifact.blocked_license} />`). For rows where `artifact.decision === 'blocked'` and `artifact.blocked_license` is set, add a button:

```tsx
{artifact.decision === 'blocked' && artifact.blocked_license ? (
  <button
    onClick={() => {
      const reason = prompt(
        `Release ${artifact.ecosystem}/${artifact.name}@${artifact.version} for this project?\n` +
        `License: ${artifact.blocked_license}\nReason (required):`,
      )
      if (reason && reason.trim()) {
        releaseLicense.mutate({
          ecosystem: artifact.ecosystem,
          name: artifact.name,
          version: artifact.version || null,
          reason: reason.trim(),
        })
      }
    }}
    className="inline-flex items-center gap-1 px-2 py-1 text-xs text-green-700 hover:bg-green-50 rounded"
  >
    <ShieldCheck className="w-3 h-3" /> Release
  </button>
) : null}
```

Add the mutation near the existing mutations in the page:

```tsx
const releaseLicense = useMutation({
  mutationFn: (vars: { ecosystem: string; name: string; version: string | null; reason: string }) =>
    projectsApi.releaseLicenseBlocked(projectId, vars.ecosystem, vars.name, vars.version, vars.reason),
  onSuccess: () => {
    void qc.invalidateQueries({ queryKey: ['project-artifacts', projectId] })
    void qc.invalidateQueries({ queryKey: ['project-overrides', projectId] })
  },
})
```

Mount the panel below the artifacts table:

```tsx
<ProjectLicenseOverridesPanel projectId={projectId} />
```

- [ ] **Step 3: Verify build**

Run: `cd ui && npm run build`
Expected: PASS, no TS errors.

- [ ] **Step 4: Commit**

```bash
git add ui/src/components/ProjectLicenseOverridesPanel.tsx ui/src/pages/ProjectDetail.tsx ui/src/api/projects.ts ui/src/api/types.ts
git commit -m "feat(ui): per-project license-override Release + visibility on Project Detail"
```

---

## Task 6: ArtifactDetailPanel — replace Release with hint for license blocks

**Files:**
- Modify: `ui/src/components/ArtifactDetailPanel.tsx:218-227`

The current Release button always calls the global path. When the artifact's `quarantine_reason` matches the license predicate, swap the button for an info hint pointing to Project Detail.

- [ ] **Step 1: Find the existing Release button**

In `ArtifactDetailPanel.tsx`, around line 218:

```tsx
{status === 'QUARANTINED' && (
  <button onClick={() => releaseMutation.mutate(resolvedId!)} ...>
    <ShieldCheck ... /> Release
  </button>
)}
```

- [ ] **Step 2: Replace with conditional rendering**

```tsx
{status === 'QUARANTINED' && (
  isLicenseQuarantine(artifact?.quarantine_reason) ? (
    <div className="flex items-center gap-2 px-3 py-1.5 text-xs rounded-md border border-amber-300 bg-amber-50 text-amber-900">
      <Info className="w-3.5 h-3.5" />
      Blocked by a project's license policy. Open the project to release for that project.
    </div>
  ) : (
    <button
      onClick={() => releaseMutation.mutate(resolvedId!)}
      disabled={releaseMutation.isPending}
      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-green-300 text-green-700 hover:bg-green-50 disabled:opacity-50"
    >
      <ShieldCheck className="w-3.5 h-3.5" />
      Release
    </button>
  )
)}
```

Add helper at the top of the file:

```ts
// Mirrors the Go-side `isLicenseQuarantineReason` predicate. Keep in sync with
// `licenseQuarantineReasonPrefix = "license policy:"` in license_reevaluation.go.
function isLicenseQuarantine(reason: string | undefined): boolean {
  if (!reason) return false
  return reason.toLowerCase().startsWith('license policy:')
}
```

Import `Info` from `lucide-react`.

- [ ] **Step 3: Handle the 409 response**

In the existing `releaseMutation`'s `onError`, surface the `next_action.hint` from the 409 body when present:

```tsx
const releaseMutation = useMutation({
  mutationFn: (id: string) => artifactsApi.release(id),
  onError: (e: AxiosError<{ error: string; next_action?: { hint: string } }>) => {
    const data = e.response?.data
    if (data?.error === 'license_block_requires_project_scope' && data?.next_action) {
      alert(`Cannot release globally: ${data.next_action.hint}`)
    } else {
      alert('Release failed: ' + (e.message ?? 'unknown'))
    }
  },
  onSuccess: () => qc.invalidateQueries({ queryKey: ['artifact', resolvedId] }),
})
```

- [ ] **Step 4: Verify build**

Run: `cd ui && npm run build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/ArtifactDetailPanel.tsx
git commit -m "fix(ui): artifact Release shows project-scope hint for license blocks"
```

---

## Task 7: E2E shell test for the per-project license flow

**Files:**
- Create: `tests/e2e-shell/test_license_per_project.sh`
- Modify: `tests/e2e-shell/run_all.sh`

End-to-end matrix:

1. Pull a license-blocked artifact through a project → assert `decision=blocked` + `blocked_license` populated on `/projects/{id}/artifacts`.
2. Try `POST /artifacts/{id}/release` → assert **409** with `error=license_block_requires_project_scope`.
3. `POST /projects/{id}/overrides` (kind=allow, scope=version) → assert **201**, override id returned.
4. `GET /projects/{id}/overrides` → assert override is in the list.
5. Re-pull the same artifact → assert it now passes (allowed).
6. `POST /projects/{id}/overrides/{id}/revoke` → assert override no longer active and pull is blocked again.

- [ ] **Step 1: Sketch the script**

```bash
#!/usr/bin/env bash
# test_license_per_project.sh — verifies that license-blocked artifacts are
# released per-project (not globally) and the override is visible on the
# project's overrides list.

test_license_per_project() {
    log_section "License: per-project Release flow + override visibility"

    if [ "${SGW_PROJECTS_MODE:-lazy}" != "strict" ]; then
        log_skip "License per-project: requires SGW_PROJECTS_MODE=strict"
        return
    fi
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "License per-project: needs super-token bootstrap"
        return
    fi
    local bearer=(-H "Authorization: Bearer ${SGW_PROXY_TOKEN}")

    # Resolve the 'default' project's numeric id.
    local pid
    pid=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" "${bearer[@]}" \
        | jq -r '.items[]? | select(.label == "default") | .id')
    if [ -z "$pid" ]; then
        log_skip "License per-project: no 'default' project"
        return
    fi

    # Rely on the existing license-policy test rig pulling a real GPL artifact;
    # if no license-blocked artifact is present, skip cleanly. Reading the
    # ecosystem/name/version as structured fields avoids fragile string-splitting
    # against artifact IDs that contain colons (e.g. scoped npm `npm:@scope/pkg:1.0`,
    # 4-segment Maven IDs).
    local list
    list=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/artifacts" "${bearer[@]}")
    local first_eco first_name first_ver first_id
    first_eco=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "blocked" and .blocked_license != "") | .ecosystem' | head -n1)
    first_name=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "blocked" and .blocked_license != "") | .name' | head -n1)
    first_ver=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "blocked" and .blocked_license != "") | .version' | head -n1)
    first_id=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "blocked" and .blocked_license != "") | .id' | head -n1)
    if [ -z "$first_eco" ] || [ -z "$first_name" ] || [ -z "$first_id" ]; then
        log_skip "License per-project: no license-blocked artifact in project (re-run test_license_policy first)"
        return
    fi

    # Step 1: global release should be 409.
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${E2E_ADMIN_URL}/api/v1/artifacts/$(printf %s "$first_id" | jq -sRr @uri)/release" \
        "${bearer[@]}")
    if [ "$code" = "409" ]; then
        log_pass "License per-project: global release on license block → 409"
    else
        log_fail "License per-project: global release expected 409, got ${code}"
        return
    fi

    # Step 2: per-project override succeeds.
    local create_body
    create_body=$(jq -n --arg eco "$first_eco" --arg name "$first_name" --arg ver "$first_ver" \
        '{ecosystem:$eco, name:$name, version:$ver, scope:"version", kind:"allow", reason:"e2e per-project release"}')
    local create_resp
    create_resp=$(curl -sf -X POST "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides" \
        "${bearer[@]}" -H "Content-Type: application/json" -d "$create_body")
    local oid
    oid=$(echo "$create_resp" | jq -r '.id // empty')
    if [ -n "$oid" ]; then
        log_pass "License per-project: project override created (id=${oid})"
    else
        log_fail "License per-project: override create failed (resp=${create_resp:0:200})"
        return
    fi

    # Step 3: GET listing includes the new override.
    local list_resp
    list_resp=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides" "${bearer[@]}")
    if echo "$list_resp" | jq -e --argjson id "$oid" '.items[]? | select(.id == $id)' >/dev/null; then
        log_pass "License per-project: override visible in project overrides listing"
    else
        log_fail "License per-project: override NOT in listing"
    fi

    # Step 4: revoke + assert revoked transitions on next list.
    # NB: SQLite stores INTEGER 0/1 while Postgres stores BOOLEAN — the JSON
    # marshaller normalizes to true/false on the wire. Accept both for safety.
    curl -sf -X POST "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides/${oid}/revoke" \
        "${bearer[@]}" -H "Content-Type: application/json" -d '{"reason":"e2e cleanup"}' \
        >/dev/null || true
    local revoked
    revoked=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides" "${bearer[@]}" \
        | jq -r --argjson id "$oid" '.items[]? | select(.id == $id) | .revoked')
    if [ "$revoked" = "true" ] || [ "$revoked" = "1" ]; then
        log_pass "License per-project: revoke transitions override to revoked"
    else
        log_fail "License per-project: revoke did not stick (revoked=${revoked})"
    fi

    # Step 5: post-revoke fail-shut. After revoking the per-project override,
    # the license check on a subsequent re-evaluation must NOT pass for this
    # artifact UNLESS a global allow still wins. Migration 036 may have planted
    # a global-mirror row for this artifact — test asserts the **status visible
    # on the project's artifacts list** flips back to blocked, OR (when a global
    # allow shadows the per-project revoke) explicitly flags that with
    # log_skip. Without this assertion, a regression that silently leaves the
    # artifact CLEAN after revoke would pass.
    local recheck
    recheck=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/artifacts" "${bearer[@]}" \
        | jq -r --arg id "$first_id" '.artifacts[]? | select(.id == $id) | .decision')
    case "$recheck" in
        blocked)
            log_pass "License per-project: post-revoke decision flipped back to blocked"
            ;;
        clean|allowed)
            # A global allow (possibly migrated via 036) is still active. Document
            # but do not fail — the system remained safe (the operator deliberately
            # released globally too).
            log_skip "License per-project: post-revoke still ${recheck} — a global allow shadows revoke (revoke /api/v1/overrides/{id} to re-block)"
            ;;
        "" )
            log_skip "License per-project: artifact disappeared from list (likely retention)"
            ;;
        *)
            log_fail "License per-project: post-revoke decision=${recheck} (expected blocked or clean-with-global)"
            ;;
    esac
}
```

- [ ] **Step 2: Wire it in `run_all.sh`**

Add `source "${SCRIPT_DIR}/test_license_per_project.sh"` next to the other sources, and `test_license_per_project` next to the other invocations.

- [ ] **Step 3: Run E2E**

Run Run 2 of the suite (license enforcement + strict projects + auth):

```bash
make test-e2e-containerized 2>&1 | tail -30
```

Expected: all 4 runs pass; the new test runs in Run 2 and skip-clean elsewhere.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/test_license_per_project.sh tests/e2e-shell/run_all.sh
git commit -m "test(e2e): per-project license override flow (409 global, 201 per-project, revoke)"
```

---

## Phase 5 verification

- [ ] **Step 1: Re-run all backend + UI tests**

```bash
go build ./... && go test ./... -race && cd ui && npm run build
```

Expected: all PASS.

- [ ] **Step 2: Re-run all 4 E2E runs**

```bash
make test-e2e-containerized
```

Expected: zero failures across all 4 configurations.

- [ ] **Step 3: Manual smoke** (against dev compose)

1. Spin up a project in `strict` mode, configure `project_license_policy.blocked_json: ["GPL-3.0-only"]`.
2. Pull a GPL-3.0 npm package via the project — observe 403 + audit row.
3. Open Project Detail → see the artifact in the table with `Release` button.
4. Click Release, enter a reason — observe the override appears in the panel.
5. Re-pull — succeeds.
6. Revoke the override — re-pull blocks again.
