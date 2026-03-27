# Shieldoo Gate v1.0 Core — Phase 7: Admin UI (React)

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a React admin dashboard SPA that displays system status, artifact management, and audit logs via the REST API.

**Architecture:** Single-page React app built with Vite, using TanStack React Query for data fetching and TailwindCSS for styling. The UI is read-heavy with action buttons for rescan/quarantine/release. Communicates with REST API on port 8080.

**Tech Stack:** React 18, TypeScript 5.x, Vite 5.x, TailwindCSS 3.x, TanStack React Query 5.x, Recharts 2.x, Radix UI, Axios, Vitest

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: Project Setup (Vite + React + TailwindCSS)

**Files:**
- Create: `ui/package.json`
- Create: `ui/tsconfig.json`
- Create: `ui/vite.config.ts`
- Create: `ui/tailwind.config.js`
- Create: `ui/postcss.config.js`
- Create: `ui/index.html`
- Create: `ui/src/main.tsx`
- Create: `ui/src/App.tsx`
- Create: `ui/src/index.css`

- [ ] **Step 1: Initialize project with Vite**

```bash
cd ui
npm create vite@latest . -- --template react-ts
```

Or create files manually with exact dependency versions from `docs/initial-analyse.md` section 4.5.

- [ ] **Step 2: Install dependencies**

```bash
cd ui
npm install react@18.3.1 react-dom@18.3.1 react-router-dom@6.23.1 \
    @tanstack/react-query@5.40.0 recharts@2.12.7 lucide-react@0.383.0 \
    @radix-ui/react-dialog@1.1.1 tailwindcss@3.4.4 axios@1.7.2
npm install -D typescript@5.5.2 vite@5.3.1 @types/react@18.3.3 vitest@1.6.0 \
    autoprefixer postcss
```

- [ ] **Step 3: Configure TailwindCSS**

```js
// ui/tailwind.config.js
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: { extend: {} },
  plugins: [],
}
```

- [ ] **Step 4: Create entry point and root component with React Router**

```tsx
// ui/src/App.tsx
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Artifacts from './pages/Artifacts'
import AuditLog from './pages/AuditLog'
import Settings from './pages/Settings'

const queryClient = new QueryClient()

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/artifacts" element={<Artifacts />} />
            <Route path="/audit-log" element={<AuditLog />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
```

- [ ] **Step 5: Verify dev server starts**

Run: `cd ui && npm run dev`
Expected: Vite dev server starts, page loads in browser.

- [ ] **Step 6: Commit**

```bash
git add ui/
git commit -m "feat(ui): initialize React project with Vite, TailwindCSS, React Query"
```

---

### Task 2: API Client

**Files:**
- Create: `ui/src/api/client.ts`
- Create: `ui/src/api/types.ts`

- [ ] **Step 1: Define TypeScript types matching API responses**

```typescript
// ui/src/api/types.ts
export interface Artifact {
  id: string
  ecosystem: string
  name: string
  version: string
  upstream_url: string
  sha256: string
  size_bytes: number
  cached_at: string
  last_accessed_at: string
  storage_path: string
}

export interface ArtifactStatus {
  artifact_id: string
  status: 'CLEAN' | 'SUSPICIOUS' | 'QUARANTINED' | 'PENDING_SCAN'
  quarantine_reason?: string
  quarantined_at?: string
  released_at?: string
}

export interface ScanResult {
  id: number
  artifact_id: string
  scanned_at: string
  scanner_name: string
  scanner_version: string
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'
  confidence: number
  findings_json: string
  duration_ms: number
}

export interface AuditEntry {
  id: number
  ts: string
  event_type: string
  artifact_id?: string
  client_ip?: string
  user_agent?: string
  reason?: string
}

export interface StatsSummary {
  total_artifacts: number
  total_blocked: number
  total_quarantined: number
  total_served: number
  by_period: Record<string, Record<string, number>>
}

export interface HealthStatus {
  status: string
  scanners: Record<string, string>
}

export interface PaginatedResponse<T> {
  data: T[]
  page: number
  per_page: number
  total: number
}
```

- [ ] **Step 2: Create Axios client with React Query hooks**

```typescript
// ui/src/api/client.ts
import axios from 'axios'
import type { Artifact, ArtifactStatus, ScanResult, AuditEntry, StatsSummary, HealthStatus, PaginatedResponse } from './types'

const api = axios.create({
  baseURL: '/api/v1',
})

export const artifactsApi = {
  list: (page = 1, perPage = 50) =>
    api.get<PaginatedResponse<Artifact & { status: ArtifactStatus }>>('/artifacts', { params: { page, per_page: perPage } }).then(r => r.data),
  get: (id: string) =>
    api.get<Artifact & { status: ArtifactStatus; scan_results: ScanResult[] }>(`/artifacts/${encodeURIComponent(id)}`).then(r => r.data),
  rescan: (id: string) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/rescan`).then(r => r.data),
  quarantine: (id: string) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/quarantine`).then(r => r.data),
  release: (id: string) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/release`).then(r => r.data),
}

export const statsApi = {
  summary: () => api.get<StatsSummary>('/stats/summary').then(r => r.data),
  blocked: () => api.get<AuditEntry[]>('/stats/blocked').then(r => r.data),
}

export const feedApi = {
  list: () => api.get('/feed').then(r => r.data),
  refresh: () => api.post('/feed/refresh').then(r => r.data),
}

export const healthApi = {
  check: () => api.get<HealthStatus>('/health').then(r => r.data),
}
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/api/
git commit -m "feat(ui): add TypeScript API client with Axios and type definitions"
```

---

### Task 3: Layout + Shared Components

**Files:**
- Create: `ui/src/components/Layout.tsx`
- Create: `ui/src/components/StatusBadge.tsx`
- Create: `ui/src/components/ArtifactTable.tsx`
- Create: `ui/src/components/ScanResultCard.tsx`

- [ ] **Step 1: Implement Layout with sidebar navigation**

Navigation links: Dashboard, Artifacts, Audit Log, Settings. Use `lucide-react` for icons. Use `Outlet` from react-router for content area.

- [ ] **Step 2: Implement StatusBadge component**

Color-coded badge for artifact status: green (CLEAN), yellow (SUSPICIOUS), red (QUARANTINED), gray (PENDING_SCAN).

- [ ] **Step 3: Implement ArtifactTable component**

Sortable table with columns: Ecosystem, Name, Version, Status, Cached At. Clickable rows for detail view.

- [ ] **Step 4: Implement ScanResultCard component**

Card displaying scan result: scanner name, verdict, confidence bar, findings list, duration.

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/
git commit -m "feat(ui): add Layout, StatusBadge, ArtifactTable, ScanResultCard components"
```

---

### Task 4: Dashboard Page

**Files:**
- Create: `ui/src/pages/Dashboard.tsx`

- [ ] **Step 1: Implement Dashboard with stats cards and traffic chart**

- Summary cards: Total Artifacts, Blocked (24h), Quarantined, Cache Size
- **Prominent warning banner** if any scanner is unhealthy (from `/health` endpoint)
- Traffic chart using Recharts (served/blocked/quarantined over time)
- Use `useQuery` from React Query for data fetching

- [ ] **Step 2: Verify page renders with mock data**

Run: `cd ui && npm run dev` — navigate to `/dashboard`

- [ ] **Step 3: Commit**

```bash
git add ui/src/pages/Dashboard.tsx
git commit -m "feat(ui): add Dashboard page with stats, scanner health warning, traffic chart"
```

---

### Task 5: Artifacts Page

**Files:**
- Create: `ui/src/pages/Artifacts.tsx`

- [ ] **Step 1: Implement Artifacts list with filtering and detail view**

- Artifact table with ecosystem/status filters
- Pagination controls
- Click row → inline detail panel or modal with:
  - Artifact metadata
  - Scan result history (using ScanResultCard)
  - Action buttons: Rescan, Quarantine, Release (conditionally shown)

- [ ] **Step 2: Commit**

```bash
git add ui/src/pages/Artifacts.tsx
git commit -m "feat(ui): add Artifacts page with filtering, detail view, and action buttons"
```

---

### Task 6: Audit Log Page

**Files:**
- Create: `ui/src/pages/AuditLog.tsx`

- [ ] **Step 1: Implement Audit Log with filtering and pagination**

- Table with columns: Timestamp, Event Type, Artifact, Client IP, Reason
- Filter by event type dropdown
- Pagination
- Sort by timestamp DESC (default)

- [ ] **Step 2: Commit**

```bash
git add ui/src/pages/AuditLog.tsx
git commit -m "feat(ui): add Audit Log page with filtering and pagination"
```

---

### Task 7: Settings Page

**Files:**
- Create: `ui/src/pages/Settings.tsx`

- [ ] **Step 1: Implement read-only Settings page**

- Display current configuration (from health/config endpoint)
- Scanner health status with green/red indicators
- v1.0 is read-only — no editing

- [ ] **Step 2: Commit**

```bash
git add ui/src/pages/Settings.tsx
git commit -m "feat(ui): add read-only Settings page with scanner health status"
```

---

### Task 8: Vite Proxy Config for Development

**Files:**
- Modify: `ui/vite.config.ts`

- [ ] **Step 1: Add proxy config for API requests in dev mode**

```typescript
// ui/vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/metrics': 'http://localhost:8080',
    },
  },
})
```

- [ ] **Step 2: Commit**

```bash
git add ui/vite.config.ts
git commit -m "chore(ui): add Vite proxy config for API in development mode"
```

---

### Task 9: Verify UI Builds

- [ ] **Step 1: Run build**

Run: `cd ui && npm run build`
Expected: Build succeeds, output in `ui/dist/`.

- [ ] **Step 2: Run type check**

Run: `cd ui && npx tsc --noEmit`
Expected: No type errors.
