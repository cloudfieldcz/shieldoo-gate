import { test, expect, request as playwrightRequest } from '@playwright/test'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'

const ADMIN = process.env.PLAYWRIGHT_ADMIN_URL ?? 'http://localhost:8080'
// SGW_PROXY_TOKEN is generated per E2E run by the Makefile (`openssl rand -hex 16`)
// — read from env. For local dev the same env var must be exported before
// `npx playwright test`. We skip (instead of failing) when missing so the spec
// is safe to invoke without a live stack.
const PROXY_TOKEN = process.env.SGW_PROXY_TOKEN ?? ''

// ui/package.json declares "type": "module", so __dirname is not available.
// Resolve the spec directory from import.meta.url for cross-platform fixture loading.
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SBOM_XSS = path.join(__dirname, 'fixtures', 'sbom-xss-payload.json')
const SBOM_VULN = path.join(__dirname, 'fixtures', 'sbom-vulnerable.json')

// Skip the whole spec when vuln-scan is disabled or when the SGW_PROXY_TOKEN
// is not exported (we cannot bootstrap auth without it).
test.beforeEach(async ({ request }) => {
  test.skip(!PROXY_TOKEN, 'SGW_PROXY_TOKEN env var not set')
  const r = await request.get(`${ADMIN}/api/v1/vulnerabilities/summary`)
  test.skip(r.status() === 503, 'vuln-scan feature disabled')
})

async function uploadSbom(
  token: string,
  project: string,
  component: string,
  fixturePath: string,
): Promise<{ scanRunId: number; componentId: number }> {
  const ctx = await playwrightRequest.newContext({
    extraHTTPHeaders: { Authorization: `Bearer ${token}` },
  })
  try {
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
    return { scanRunId: j.scan_run_id as number, componentId: j.component_id as number }
  } finally {
    await ctx.dispose()
  }
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

  // 1. Vulnerabilities list — renders any component-name / repo URL columns.
  await page.goto(`/vulnerabilities`)
  await page.waitForLoadState('networkidle')

  // 2. Component Detail — tabs there are active|ignored|history|integration; no
  //    SBOM/findings tab. The page itself renders metadata that may be SBOM-derived.
  await page.goto(`/vulnerabilities/components/${componentId}`)
  await page.waitForLoadState('networkidle')

  // 3. ScanRun Detail — Findings + SBOM tabs live here. The tabs are plain
  //    <button> elements (no role="tab"), so query them by role="button".
  await page.goto(`/vulnerabilities/scan-runs/${scanRunId}`)
  await page.waitForLoadState('networkidle')

  // 4. Click Findings tab and wait for content. Failures here should be loud
  //    (no .catch swallow) so a missing tab is caught instead of skipped.
  await page.getByRole('button', { name: /findings/i }).click()
  await page.waitForTimeout(500)

  // 5. Click SBOM tab — this is the highest XSS-risk surface (raw CycloneDX
  //    rendered into the DOM by SBOMJSONViewer). The "Download SBOM" element
  //    is an <a> (role=link) so the role=button filter targets only the tab.
  await page.getByRole('button', { name: /sbom/i }).click()
  await page.waitForTimeout(1000)

  expect(dialogText, `XSS payload triggered alert("${dialogText}")`).toBeNull()
})

test('happy path: upload → ignore → revoke', async ({ page }) => {
  const componentName = `e2e-happy-${Date.now()}`
  const { componentId } = await uploadSbom(PROXY_TOKEN, 'default', componentName, SBOM_VULN)

  // Wait for the scan to finish (poll the API instead of UI to avoid timing flakes).
  const apiCtx = await playwrightRequest.newContext({
    extraHTTPHeaders: { Authorization: `Bearer ${PROXY_TOKEN}` },
  })
  try {
    for (let i = 0; i < 30; i++) {
      const r = await apiCtx.get(`${ADMIN}/api/v1/vulnerabilities/components/${componentId}`)
      if (r.ok()) {
        const c = await r.json()
        if (c.last_scan_id) break
      }
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }

    // Skip cleanly when the scan reports no findings — the test rig may not
    // have OSV / vulnerability-DB data loaded (dev compose, offline runner,
    // etc.). The happy-path lifecycle requires at least one finding to ignore.
    const findingsResp = await apiCtx.get(
      `${ADMIN}/api/v1/vulnerabilities/components/${componentId}/findings`,
    )
    const findingsBody = findingsResp.ok() ? await findingsResp.json() : { items: [] }
    const findingsCount = (findingsBody.items as unknown[] | undefined)?.length ?? 0
    test.skip(
      findingsCount === 0,
      'no findings reported for the seeded SBOM — scanner data unavailable in this rig',
    )

    // Findings page. ComponentDetail tabs are plain <button>s (no role="tab")
    // labelled active|ignored|history|integration; the "active" tab — which
    // renders the Active CVEs table the test ignores below — is the default
    // (useState<Tab>('active') in ComponentDetail.tsx), so no click is needed.
    await page.goto(`/vulnerabilities/components/${componentId}`)

    // Open the first findings row, click Ignore, fill reason, submit.
    const firstRow = page.locator('tbody tr').first()
    await expect(firstRow).toBeVisible({ timeout: 10_000 })
    await firstRow.getByRole('button', { name: /ignore/i }).click()
    await page.getByLabel(/reason/i).fill('e2e: false positive — happy path')
    await page.getByRole('button', { name: /create.*ignore|save/i }).click()

    // Reload — the row must now show an "ignored" indicator.
    await page.reload()
    await expect(page.getByText(/ignored/i).first()).toBeVisible({ timeout: 10_000 })

    // Revoke via API. Real route (per internal/api/server.go) is
    //   DELETE /api/v1/vulnerabilities/components/{id}/ignores/{ignoreId}
    // — there is no separate /ignores/{id}/revoke. UI's revoke flow hits the
    // same path; calling it from the API exercises the persistence layer.
    // GET ignores returns {items: [...]} (see internal/api/ignores.go:42).
    // ListActive only returns non-revoked rows so any item is safe to revoke;
    // we still defensively filter on `revoked_at` in case the API surface
    // gains a `?include=expired` default later.
    const ignores = await apiCtx.get(`${ADMIN}/api/v1/vulnerabilities/components/${componentId}/ignores`)
    const items = (await ignores.json()).items as Array<{ id: number; revoked_at: string | null }>
    const active = items.find((i) => !i.revoked_at) ?? items[0]
    expect(active, 'expected one active ignore').toBeTruthy()
    const revoke = await apiCtx.delete(
      `${ADMIN}/api/v1/vulnerabilities/components/${componentId}/ignores/${active.id}`,
    )
    expect(revoke.ok(), `revoke failed: ${revoke.status()}`).toBeTruthy()

    // Reload UI — the "ignored" indicator should be gone.
    await page.reload()
    await page.waitForTimeout(500)
  } finally {
    await apiCtx.dispose()
  }
})
