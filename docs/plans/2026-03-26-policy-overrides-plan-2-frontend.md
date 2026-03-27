# Policy Overrides — Phase 2: Frontend

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add "Mark as False Positive" button to artifact detail panel and a new Overrides management page in the admin UI.

**Architecture:** New TypeScript types for overrides, new API client methods, a "false positive" button in the existing Artifacts detail panel, and a new Overrides page with a table listing all overrides with ability to revoke.

**Tech Stack:** React 18, TypeScript, TanStack React Query, TailwindCSS, Lucide React, Axios

**Index:** [`plan-index.md`](./2026-03-26-policy-overrides-plan-index.md)

**Prerequisite:** Phase 1 (backend) must be complete — API endpoints must exist.

---

### Task 1: TypeScript Types + API Client

**Files:**
- Modify: `ui/src/api/types.ts` (add PolicyOverride interface)
- Modify: `ui/src/api/client.ts` (add overridesApi + artifactOverride method)

- [ ] **Step 1: Add PolicyOverride type**

Add to `ui/src/api/types.ts` after the `AuditEntry` interface (line 42):

```typescript
export interface PolicyOverride {
  id: number
  ecosystem: string
  name: string
  version: string
  scope: 'version' | 'package'
  reason: string
  created_by: string
  created_at: string
  expires_at?: string
  revoked: boolean
  revoked_at?: string
}
```

- [ ] **Step 2: Add API client methods**

Add to `ui/src/api/client.ts` — add `PolicyOverride` to the import from `./types`, then add after `feedApi`:

```typescript
export const overridesApi = {
  list: (page = 1, perPage = 50, active?: boolean) =>
    api
      .get<PaginatedResponse<PolicyOverride>>('/overrides', {
        params: { page, per_page: perPage, active: active ? 'true' : undefined },
      })
      .then((r) => r.data),

  create: (data: { ecosystem: string; name: string; version: string; scope: string; reason: string }) =>
    api.post('/overrides', data).then((r) => r.data),

  revoke: (id: number) =>
    api.delete(`/overrides/${id}`).then((r) => r.data),
}
```

Also add to `artifactsApi`:

```typescript
  override: (id: string, data?: { reason?: string; scope?: string }) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/override`, data ?? {}).then((r) => r.data),
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/api/types.ts ui/src/api/client.ts
git commit -m "feat(ui): add policy override types and API client methods"
```

---

### Task 2: "Mark as False Positive" Button in Artifact Detail

**Files:**
- Modify: `ui/src/pages/Artifacts.tsx` (add override mutation + button)

- [ ] **Step 1: Add override mutation**

In `ui/src/pages/Artifacts.tsx`, add the import of `artifactsApi` already exists. Add a new mutation after `releaseMutation` (after line 62):

```typescript
  const overrideMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.override(id, { reason: 'false positive', scope: 'version' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', selected?.id] })
    },
  })
```

- [ ] **Step 2: Add the button to the action buttons section**

In the action buttons `div` (around line 199-230), add a "False Positive" button. It should show when the artifact status is `QUARANTINED` or `SUSPICIOUS` (i.e., when the artifact was blocked/quarantined by scanner and needs override). Add it after the Release button block:

Add import for `ShieldAlert` from lucide-react (line 8):

```typescript
import { X, RefreshCw, ShieldX, ShieldCheck, ShieldAlert, ChevronLeft, ChevronRight } from 'lucide-react'
```

Then add the button after the Release button (after line 229):

```tsx
                {(selected.status.status === 'QUARANTINED' || selected.status.status === 'SUSPICIOUS') && (
                  <button
                    onClick={() => overrideMutation.mutate(selected.id)}
                    disabled={overrideMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-amber-300 text-amber-700 hover:bg-amber-50 disabled:opacity-50"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    False Positive
                  </button>
                )}
```

- [ ] **Step 3: Verify locally**

Run: `cd ui && npm run build`
Expected: Builds without errors.

- [ ] **Step 4: Commit**

```bash
git add ui/src/pages/Artifacts.tsx
git commit -m "feat(ui): add 'False Positive' button to artifact detail panel"
```

---

### Task 3: Overrides Management Page

**Files:**
- Create: `ui/src/pages/Overrides.tsx`
- Modify: `ui/src/App.tsx` (add route)
- Modify: `ui/src/components/Layout.tsx` (add nav item)

- [ ] **Step 1: Create the Overrides page**

Create `ui/src/pages/Overrides.tsx`:

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { overridesApi } from '../api/client'
import type { PolicyOverride } from '../api/types'
import { Trash2, ChevronLeft, ChevronRight } from 'lucide-react'

const PER_PAGE = 20

function scopeLabel(scope: string) {
  return scope === 'package' ? 'All versions' : 'Exact version'
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

export default function Overrides() {
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [activeOnly, setActiveOnly] = useState(true)

  const listQuery = useQuery({
    queryKey: ['overrides', page, activeOnly],
    queryFn: () => overridesApi.list(page, PER_PAGE, activeOnly || undefined),
    retry: 1,
  })

  const revokeMutation = useMutation({
    mutationFn: (id: number) => overridesApi.revoke(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['overrides'] })
    },
  })

  const overrides = listQuery.data?.data ?? []
  const total = listQuery.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  return (
    <div className="p-8 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Policy Overrides</h1>
        <p className="text-sm text-gray-500 mt-1">Manage false-positive exceptions for blocked artifacts</p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-gray-700">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => { setActiveOnly(e.target.checked); setPage(1) }}
            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          />
          Active only
        </label>
        <span className="text-sm text-gray-500 ml-auto">
          {listQuery.isLoading ? 'Loading...' : `${total} override${total !== 1 ? 's' : ''}`}
        </span>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        {listQuery.isError ? (
          <div className="p-8 text-center text-red-500 text-sm">
            Failed to load overrides. Is the API server running?
          </div>
        ) : (
          <table className="w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Package</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scope</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reason</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {overrides.map((o: PolicyOverride) => (
                <tr key={o.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-sm">
                    <span className="font-mono text-gray-800">{o.ecosystem}/{o.name}</span>
                    {o.version && (
                      <span className="font-mono text-gray-500 ml-1">@{o.version}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">{scopeLabel(o.scope)}</td>
                  <td className="px-4 py-3 text-sm text-gray-600 max-w-xs truncate">{o.reason || '—'}</td>
                  <td className="px-4 py-3 text-sm text-gray-500">{formatDate(o.created_at)}</td>
                  <td className="px-4 py-3 text-sm">
                    {o.revoked ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                        Revoked
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700">
                        Active
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {!o.revoked && (
                      <button
                        onClick={() => revokeMutation.mutate(o.id)}
                        disabled={revokeMutation.isPending}
                        className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border border-red-200 text-red-600 hover:bg-red-50 disabled:opacity-50"
                        title="Revoke this override"
                      >
                        <Trash2 className="w-3 h-3" />
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {overrides.length === 0 && !listQuery.isLoading && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-sm text-gray-400">
                    No overrides found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="flex items-center gap-1 text-sm text-gray-600 disabled:opacity-40 hover:text-blue-600"
            >
              <ChevronLeft className="w-4 h-4" /> Previous
            </button>
            <span className="text-sm text-gray-500">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="flex items-center gap-1 text-sm text-gray-600 disabled:opacity-40 hover:text-blue-600"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Add route to App.tsx**

In `ui/src/App.tsx`, add import:

```typescript
import Overrides from './pages/Overrides'
```

Add route after the artifacts route (after line 26):

```tsx
            <Route path="/overrides" element={<Overrides />} />
```

- [ ] **Step 3: Add nav item to Layout.tsx**

In `ui/src/components/Layout.tsx`, add `ShieldAlert` to lucide-react import (line 2):

```typescript
import { LayoutDashboard, Package, ScrollText, Settings, ShieldCheck, ShieldAlert } from 'lucide-react'
```

Add nav item to the `navItems` array after Artifacts (after line 6):

```typescript
  { to: '/overrides', label: 'Overrides', icon: ShieldAlert },
```

The full navItems array should be:

```typescript
const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/artifacts', label: 'Artifacts', icon: Package },
  { to: '/overrides', label: 'Overrides', icon: ShieldAlert },
  { to: '/audit-log', label: 'Audit Log', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: Settings },
]
```

- [ ] **Step 4: Build and verify**

Run: `cd ui && npm run build`
Expected: Builds without TypeScript errors.

- [ ] **Step 5: Commit**

```bash
git add ui/src/pages/Overrides.tsx ui/src/App.tsx ui/src/components/Layout.tsx
git commit -m "feat(ui): add Overrides management page with revoke support"
```
