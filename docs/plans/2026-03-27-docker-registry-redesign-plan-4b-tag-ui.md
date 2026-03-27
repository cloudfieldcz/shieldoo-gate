# Docker Registry Redesign — Phase 4b: Tag Management UI

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admin UI for Docker repository listing, tag management, sync status monitoring, and manual sync trigger.

**Architecture:** New React components in the admin UI (`ui/`) using existing patterns (TanStack React Query for data fetching, TailwindCSS for styling, Radix UI for primitives). Components call the REST API from Phase 4a. Pages: Docker Repositories list (filterable by registry), Repository detail with tags, Sync status + manual trigger.

**Tech Stack:** React 18, TypeScript 5.x, TanStack React Query, TailwindCSS, Radix UI, Axios

**Index:** [`plan-index.md`](./2026-03-27-docker-registry-redesign-plan-index.md)

---

### Task 1: API Client Hooks

**Files:**
- Create: `ui/src/hooks/useDockerRepositories.ts`
- Create: `ui/src/hooks/useDockerTags.ts`

- [ ] **Step 1: Explore existing UI patterns**

Read existing hooks in `ui/src/hooks/` to understand data fetching patterns (React Query keys, Axios usage, error handling).

- [ ] **Step 2: Implement useDockerRepositories hook**

```typescript
// ui/src/hooks/useDockerRepositories.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';

export interface DockerRepository {
  id: number;
  registry: string;
  name: string;
  is_internal: boolean;
  created_at: string;
  last_synced_at: string | null;
  sync_enabled: boolean;
}

export function useDockerRepositories(registry?: string) {
  return useQuery({
    queryKey: ['docker-repositories', registry],
    queryFn: async () => {
      const params = registry ? { registry } : {};
      const { data } = await axios.get<DockerRepository[]>('/api/v1/docker/repositories', { params });
      return data;
    },
  });
}

export function useTriggerSync() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (repoId: number) => {
      await axios.post(`/api/v1/docker/sync/${repoId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['docker-repositories'] });
    },
  });
}
```

- [ ] **Step 3: Implement useDockerTags hook**

```typescript
// ui/src/hooks/useDockerTags.ts
// useDockerTags(repoId), useCreateTag(), useDeleteTag()
```

- [ ] **Step 4: Commit**

```bash
git add ui/src/hooks/useDockerRepositories.ts ui/src/hooks/useDockerTags.ts
git commit -m "feat(ui): add React Query hooks for Docker API"
```

---

### Task 2: Docker Repositories List Page

**Files:**
- Create: `ui/src/pages/DockerRepositoriesPage.tsx`

- [ ] **Step 1: Explore existing page patterns**

Read existing pages in `ui/src/pages/` to understand layout, navigation, table patterns.

- [ ] **Step 2: Implement repositories list page**

Features:
- Table with columns: Registry, Name, Internal?, Last Synced, Sync Enabled, Actions
- Filter dropdown by registry
- Sync trigger button per row
- Link to repository detail (tags)

- [ ] **Step 3: Add navigation entry**

Add route and nav link for the Docker Repositories page.

- [ ] **Step 4: Commit**

```bash
git add ui/src/pages/DockerRepositoriesPage.tsx ui/src/App.tsx
git commit -m "feat(ui): Docker repositories list page"
```

---

### Task 3: Repository Detail — Tags Management

**Files:**
- Create: `ui/src/pages/DockerRepositoryDetailPage.tsx`

- [ ] **Step 1: Implement tag list + management**

Features:
- Tag table: Tag, Manifest Digest, Artifact Status, Created, Updated
- Create tag form (tag name + digest)
- Delete tag button with confirmation
- Sync status indicator
- Manual sync trigger button

- [ ] **Step 2: Commit**

```bash
git add ui/src/pages/DockerRepositoryDetailPage.tsx
git commit -m "feat(ui): Docker repository detail page with tag management"
```

---

### Task 4: Final Verification

- [ ] **Step 1: Build UI**

Run: `cd /Users/valda/src/projects/shieldoo-gate/ui && npm run build`
Expected: Builds without errors

- [ ] **Step 2: Run UI linter**

Run: `cd /Users/valda/src/projects/shieldoo-gate/ui && npm run lint`
Expected: No new warnings

- [ ] **Step 3: Run full backend test suite**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./... -count=1`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add ui/
git commit -m "feat(ui): complete Docker tag management UI"
```
