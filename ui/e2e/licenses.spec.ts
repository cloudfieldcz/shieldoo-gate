import { test, expect } from '@playwright/test'

test('chalk artifact detail shows MIT license badge', async ({ page }) => {
  await page.goto('/artifacts')

  // Wait for the artifact table to load and find chalk.
  const chalkRow = page.locator('tr', { hasText: 'chalk' }).first()
  await expect(chalkRow).toBeVisible({ timeout: 10_000 })

  // Click the chalk row to open the detail panel.
  await chalkRow.click()
  await expect(page.locator('h2', { hasText: 'chalk' })).toBeVisible({ timeout: 5_000 })

  // Licenses section should appear with MIT badge.
  await expect(page.getByText('Licenses')).toBeVisible({ timeout: 10_000 })
  await expect(page.locator('span', { hasText: 'MIT' })).toBeVisible()
})
