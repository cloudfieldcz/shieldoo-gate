import { test, expect } from '@playwright/test'

// Functional flow: an artifact's license metadata surfaces in the detail panel.
// Requires a populated gate where the `chalk` npm artifact has been proxied and
// scanned (the shell e2e / dev compose seed it). On the standalone UI suite's
// empty gate there is no such row, so the test self-skips rather than failing.
test('chalk artifact detail shows MIT license badge', async ({ page }) => {
  await page.goto('/artifacts')
  await page.waitForLoadState('networkidle')

  const chalkRow = page.locator('tr', { hasText: 'chalk' }).first()
  test.skip(
    !(await chalkRow.isVisible().catch(() => false)),
    'no chalk artifact present — run against a populated gate (dev compose / shell e2e)',
  )

  // Click the chalk row to open the detail panel.
  await chalkRow.click()
  await expect(page.locator('h2', { hasText: 'chalk' })).toBeVisible({ timeout: 5_000 })

  // Licenses section should appear with MIT badge.
  await expect(page.getByText('Licenses')).toBeVisible({ timeout: 10_000 })
  await expect(page.locator('span', { hasText: 'MIT' })).toBeVisible()
})
