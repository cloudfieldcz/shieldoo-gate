import { test } from '@playwright/test'
import { gotoStable, stableShot } from '../support/visual'

// Visual-regression baselines for every top-level page in its empty / default
// state. A freshly-brought-up gate has no artifacts, projects, scans, etc., so
// these views are deterministic by construction — no seeding required.
//
// Data-driven detail pages (/projects/:id, /vulnerabilities/components/:id,
// /vulnerabilities/scan-runs/:id, /docker/repositories/:id) need seeded
// entities and are exercised by the token-gated flow specs instead.
//
// Baselines MUST be generated in the pinned Playwright container
// (mcr.microsoft.com/playwright:v1.61.0-jammy) — see docs/development/ui-e2e.md —
// so dev (macOS) and CI (Linux) render byte-identically.

interface PageCase {
  name: string
  route: string
  // Page-body regions that are volatile even on an empty gate (e.g. the audit
  // log's startup rows carry timestamps). Masked by CSS selector.
  maskSelectors?: string[]
}

const PAGES: PageCase[] = [
  { name: 'dashboard', route: '/dashboard' },
  { name: 'artifacts', route: '/artifacts' },
  { name: 'projects', route: '/projects' },
  { name: 'vulnerabilities', route: '/vulnerabilities' },
  { name: 'license-policy', route: '/license-policy' },
  { name: 'docker', route: '/docker' },
  { name: 'overrides', route: '/overrides' },
  // NOTE: /audit-log is deliberately NOT visually snapshotted. A fresh gate
  // emits a variable number of startup/config audit rows, so the table height
  // (and therefore everything below it) is not reproducible across boots. The
  // page is still covered structurally by flows/navigation.spec.ts.
  // Settings surfaces runtime values (uptime/version) that drift between runs.
  { name: 'settings', route: '/settings', maskSelectors: ['main time'] },
  { name: 'profile', route: '/profile' },
]

for (const p of PAGES) {
  test(`visual: ${p.name} (empty state)`, async ({ page }) => {
    await gotoStable(page, p.route)
    const extraMasks = (p.maskSelectors ?? []).map((sel) => page.locator(sel))
    await stableShot(page, `${p.name}.png`, extraMasks)
  })
}
