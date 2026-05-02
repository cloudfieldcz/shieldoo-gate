import { test, expect, request as playwrightRequest } from '@playwright/test'

const ADMIN = 'http://localhost:8080'
const NPM_PROXY = 'http://localhost:4873'
// edit-distance 2 from "lodash"; npm "security holding package", harmless.
const TYPO_NAME = 'lodsah'
const ARTIFACT_ID = `npm:${TYPO_NAME}:*`
const ARTIFACT_ID_ENC = encodeURIComponent(ARTIFACT_ID)
// docker-compose well-known dev token; required when proxy auth is enabled.
const PROXY_USER = 'ci-bot'
const PROXY_TOKEN = 'test-token-123'

test('typosquat block is overridable from the artifacts pane', async ({ page }) => {
  // Admin context: no auth needed for the admin API in the dev compose.
  const adminCtx = await playwrightRequest.newContext()
  // Proxy context: send Basic auth that the gate's proxy ports require.
  const proxyCtx = await playwrightRequest.newContext({
    httpCredentials: { username: PROXY_USER, password: PROXY_TOKEN },
  })

  // Reset state so the test is idempotent across runs: revoke any existing
  // override for the typosquat name, then delete the synthetic artifact row.
  const overrides = await adminCtx.get(`${ADMIN}/api/v1/overrides?ecosystem=npm`)
  if (overrides.ok()) {
    const body: { data?: Array<{ id: number; name: string; revoked: boolean }> } = await overrides.json()
    for (const o of body.data ?? []) {
      if (o.name === TYPO_NAME && !o.revoked) {
        await adminCtx.delete(`${ADMIN}/api/v1/overrides/${o.id}`)
      }
    }
  }
  await adminCtx.delete(`${ADMIN}/api/v1/artifacts/${ARTIFACT_ID_ENC}`)

  // 1. Trigger a typosquat block by hitting the npm proxy with a known
  // typosquat name — pre-scan should return HTTP 403 and persist a
  // synthetic artifact row.
  const blocked = await proxyCtx.get(`${NPM_PROXY}/${TYPO_NAME}`)
  expect(blocked.status(), `expected typosquat pre-scan to block ${TYPO_NAME}`).toBe(403)

  // 2. Navigate to the Artifacts pane and locate the QUARANTINED row.
  await page.goto('/artifacts')

  const lodsahRow = page.locator('tr', { hasText: TYPO_NAME }).first()
  await expect(lodsahRow).toBeVisible({ timeout: 10_000 })
  await expect(lodsahRow).toContainText('(any version)', { timeout: 5_000 })
  await expect(lodsahRow).toContainText(/quarantined/i)

  // 3. Open the detail panel and click Release.
  await lodsahRow.click()
  const detailHeading = page.locator('h2', { hasText: TYPO_NAME })
  await expect(detailHeading).toBeVisible({ timeout: 5_000 })
  // The quarantine reason and the scan-result card both reference typosquat;
  // first() avoids strict-mode failure across multiple matches.
  await expect(page.getByText(/typosquat/i).first()).toBeVisible()

  await page.getByRole('button', { name: 'Release' }).click()

  // 4. Active-override block should appear with the package-scope label.
  await expect(page.getByText('Active Override')).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText('All versions')).toBeVisible()

  // 5. Refetch the same name through the proxy — must succeed (proxied to
  // upstream). lodsah is npm's "security holding package" so upstream returns
  // 200; assert a real 2xx range so unrelated errors (5xx, network, etc.) do
  // not silently pass.
  const recheck = await proxyCtx.get(`${NPM_PROXY}/${TYPO_NAME}`)
  expect(
    recheck.status(),
    `expected ${TYPO_NAME} to be allowed (2xx) after override; got ${recheck.status()}`,
  ).toBeGreaterThanOrEqual(200)
  expect(recheck.status()).toBeLessThan(300)

  await proxyCtx.dispose()
  await adminCtx.dispose()
})
