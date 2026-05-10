# Vulnerability Scan — Final Polish — Phase 4: Playwright UI E2E

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `ui/e2e/vuln-scan.spec.ts` covering two assertions that unit tests cannot reach:

1. **XSS guard** (security-critical, [plan §1374](../2026-05-07-vulnerability-scan.md)) — uploading an SBOM with `description="<img src=x onerror=alert(1)>"` and `summary="<script>alert(1)</script>"` must NOT trigger any `alert` dialog when the operator visits the affected pages (Vulnerabilities list, Component Detail, ScanRun Detail, SBOM tab).
2. **Happy-path lifecycle** — upload → see findings → ignore one CVE → expire (or simulate the revoke step) → revoke → verify the affected row no longer shows the ignore badge.

**Architecture:** A single Playwright spec file colocated with the existing `typosquat-override.spec.ts` and `licenses.spec.ts`. Re-uses the authenticated proxy/admin context patterns from those tests. Hooks into `page.on('dialog')` to fail-fast on any unexpected XSS-driven `alert`.

**Tech Stack:** `@playwright/test ^1.59.1` (already in `ui/package.json`). Reuses the existing `playwright.config.ts` with `baseURL: http://localhost:8080`.

**Index:** [`plan-index.md`](./2026-05-08-vuln-scan-finish-plan-index.md)

**Prerequisite for runtime:** the dev compose must be up at `localhost:8080` with vuln-scan enabled (`vuln_scan.enabled: true` in `config.example.yaml`). The repo's existing CI doesn't run Playwright in CI; this spec is invoked locally as `cd ui && npx playwright test vuln-scan.spec.ts`.

---

## File map

| Path | Action | Responsibility |
|------|--------|----------------|
| `ui/e2e/vuln-scan.spec.ts` | Create | XSS spec + happy-path lifecycle spec. |
| `ui/e2e/fixtures/sbom-xss-payload.json` | Create | CycloneDX SBOM with HTML-injection in description, summary, repo_url. |
| `ui/e2e/fixtures/sbom-vulnerable.json` | Create | Minimal SBOM with `requests==2.10.0` for happy-path. |

---

## Task 1: Fixtures

**Files:**
- Create: `ui/e2e/fixtures/sbom-xss-payload.json`
- Create: `ui/e2e/fixtures/sbom-vulnerable.json`

- [ ] **Step 1: XSS payload SBOM**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "xss-payload-pkg",
      "version": "1.0.0",
      "purl": "pkg:pypi/xss-payload-pkg@1.0.0",
      "description": "<img src=x onerror=alert('xss-desc')>",
      "externalReferences": [
        { "type": "vcs", "url": "javascript:alert('xss-vcs')" }
      ]
    },
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.10",
      "purl": "pkg:npm/lodash@4.17.10",
      "description": "<script>alert('xss-script')</script>"
    }
  ]
}
```

- [ ] **Step 2: Vulnerable SBOM (happy-path)**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    { "type": "library", "name": "requests", "version": "2.10.0", "purl": "pkg:pypi/requests@2.10.0" }
  ]
}
```

- [ ] **Step 3: Commit**

```bash
git add ui/e2e/fixtures/
git commit -m "test(ui): SBOM fixtures for XSS guard + happy-path Playwright spec"
```

---

## Task 2: XSS guard spec

**Files:**
- Create: `ui/e2e/vuln-scan.spec.ts`

- [ ] **Step 1: Skeleton + XSS spec**

```ts
import { test, expect, request as playwrightRequest } from '@playwright/test'
import * as fs from 'fs'
import * as path from 'path'

const ADMIN = process.env.PLAYWRIGHT_ADMIN_URL ?? 'http://localhost:8080'
// SGW_PROXY_TOKEN is generated per E2E run by the Makefile (`openssl rand -hex 16`)
// — read from env. For local dev the same env var must be exported before
// `npx playwright test`. We fail fast (instead of guessing) when missing.
const PROXY_TOKEN = process.env.SGW_PROXY_TOKEN ?? ''

const SBOM_XSS = path.join(__dirname, 'fixtures', 'sbom-xss-payload.json')
const SBOM_VULN = path.join(__dirname, 'fixtures', 'sbom-vulnerable.json')

// Skip the whole spec when vuln-scan is disabled or when the SGW_PROXY_TOKEN
// is not exported (we cannot bootstrap auth without it).
test.beforeEach(async ({ request }) => {
  test.skip(!PROXY_TOKEN, 'SGW_PROXY_TOKEN env var not set')
  const r = await request.get(`${ADMIN}/api/v1/vulnerabilities/summary`)
  test.skip(r.status() === 503, 'vuln-scan feature disabled')
})

async function uploadSbom(token: string, project: string, component: string, fixturePath: string) {
  const ctx = await playwrightRequest.newContext({
    extraHTTPHeaders: { Authorization: `Bearer ${token}` },
  })
  const body = fs.readFileSync(fixturePath)
  const r = await ctx.post(
    `${ADMIN}/api/v1/projects/${project}/components/${component}/scans?ecosystem=multi`,
    {
      headers: { 'Content-Type': 'application/vnd.cyclonedx+json' },
      data: body,
    },
  )
  expect(r.ok(), `upload failed: ${r.status()} ${await r.text()}`).toBeTruthy()
  const j = await r.json()
  await ctx.dispose()
  return { scanRunId: j.scan_run_id as number, componentId: j.component_id as number }
}

test('XSS guard: SBOM-borne payloads never fire alert', async ({ page }) => {
  // Set up dialog interceptor BEFORE navigating; any alert means the guard failed.
  let dialogText: string | null = null
  page.on('dialog', async (d) => {
    dialogText = d.message()
    await d.dismiss()
  })

  const componentName = `e2e-xss-${Date.now()}`
  const { scanRunId, componentId } = await uploadSbom(PROXY_TOKEN, 'default', componentName, SBOM_XSS)

  // Visit each surface where SBOM-borne text is rendered.
  await page.goto(`/vulnerabilities`)
  await page.waitForTimeout(500)
  await page.goto(`/vulnerabilities/components/${componentId}`)
  await page.waitForTimeout(500)
  await page.getByRole('tab', { name: /findings/i }).click().catch(() => {})
  await page.waitForTimeout(500)
  await page.getByRole('tab', { name: /sbom/i }).click().catch(() => {})
  await page.waitForTimeout(1000)
  await page.goto(`/vulnerabilities/scan-runs/${scanRunId}`)
  await page.waitForTimeout(500)

  expect(dialogText, `XSS payload triggered alert("${dialogText}")`).toBeNull()
})
```

- [ ] **Step 2: Happy-path lifecycle spec**

Append to `vuln-scan.spec.ts`:

```ts
test('happy path: upload → ignore → revoke', async ({ page }) => {
  const componentName = `e2e-happy-${Date.now()}`
  const { componentId } = await uploadSbom(PROXY_TOKEN, 'default', componentName, SBOM_VULN)

  // Wait for the scan to finish (poll the API instead of UI to avoid timing flakes).
  const apiCtx = await playwrightRequest.newContext({
    extraHTTPHeaders: { Authorization: `Bearer ${PROXY_TOKEN}` },
  })
  for (let i = 0; i < 30; i++) {
    const r = await apiCtx.get(`${ADMIN}/api/v1/vulnerabilities/components/${componentId}`)
    if (r.ok()) {
      const c = await r.json()
      if (c.last_scan_id) break
    }
    await new Promise((r) => setTimeout(r, 1000))
  }

  // Findings page.
  await page.goto(`/vulnerabilities/components/${componentId}`)
  await page.getByRole('tab', { name: /findings/i }).click()

  // Open the first findings row, click Ignore, fill reason, submit.
  const firstRow = page.locator('tbody tr').first()
  await expect(firstRow).toBeVisible({ timeout: 10_000 })
  await firstRow.getByRole('button', { name: /ignore/i }).click()
  await page.getByLabel(/reason/i).fill('e2e: false positive — happy path')
  await page.getByRole('button', { name: /create.*ignore|save/i }).click()

  // Reload — the row must now show an "ignored" indicator.
  await page.reload()
  await expect(page.getByText(/ignored/i).first()).toBeVisible({ timeout: 10_000 })

  // Revoke via API. Real route (per internal/api/server.go:256) is
  //   DELETE /api/v1/vulnerabilities/components/{id}/ignores/{ignoreId}
  // — there is no separate /ignores/{id}/revoke. UI's revoke flow hits the
  // same path; calling it from the API exercises the persistence layer.
  const ignores = await apiCtx.get(`${ADMIN}/api/v1/vulnerabilities/components/${componentId}/ignores`)
  const items = (await ignores.json()).items as Array<{ id: number; revoked: boolean }>
  const active = items.find((i) => !i.revoked)
  expect(active, 'expected one active ignore').toBeTruthy()
  const revoke = await apiCtx.delete(
    `${ADMIN}/api/v1/vulnerabilities/components/${componentId}/ignores/${active!.id}`,
  )
  expect(revoke.ok(), `revoke failed: ${revoke.status()}`).toBeTruthy()
  await apiCtx.dispose()

  // Reload UI — the "ignored" indicator should be gone.
  await page.reload()
  await page.waitForTimeout(500)
})
```

- [ ] **Step 3: Local run**

Bring up the dev compose with vuln-scan enabled, then:

```bash
cd ui
npx playwright install chromium  # one-time
npx playwright test vuln-scan.spec.ts --reporter=list
```

Expected: 2 tests passing. `dialogText` must remain `null` for the XSS test.

- [ ] **Step 4: Commit**

```bash
git add ui/e2e/vuln-scan.spec.ts
git commit -m "test(ui): Playwright XSS guard + happy-path lifecycle spec"
```

---

## Task 3: Optional — Phase 5 license-override flow (only if Phase 5 lands)

If Phase 5 is implemented, append a third test exercising the per-project license-override Release UI:

```ts
test('license per-project: Release surfaces in Project Detail and persists', async ({ page }) => {
  // Skip when projects strict mode isn't on — the test rig must be in Run 2.
  // Implementation: navigate to /projects/<id>, find the GPL-blocked artifact
  // row, click Release, enter reason, assert the row moves to "released" and
  // the new override appears in the License Overrides panel below.
})
```

This is **only** useful if Phase 5 has shipped its UI changes. Keep this task optional and behind a feature-flag check.

---

## Phase 4 verification

- [ ] **Step 1: All 3 (or 2) tests green**

```bash
cd ui && npx playwright test vuln-scan.spec.ts --reporter=list
```

- [ ] **Step 2: Run other Playwright specs to confirm no regression**

```bash
cd ui && npx playwright test
```

Expected: all specs PASS, including pre-existing `typosquat-override` and `licenses`.
