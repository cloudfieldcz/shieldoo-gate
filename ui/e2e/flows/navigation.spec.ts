import { test, expect, type Page } from '@playwright/test'

// Interaction-flow coverage for the global shell: the root redirect, sidebar
// navigation across every top-level page, the active-link highlight, and a
// console-error guard so a page that throws on mount fails loudly instead of
// silently rendering an empty frame.

const NAV = [
  { label: 'Dashboard', path: '/dashboard', heading: 'Dashboard' },
  { label: 'Artifacts', path: '/artifacts', heading: 'Artifacts' },
  { label: 'Projects', path: '/projects', heading: 'Projects' },
  { label: 'Vulnerabilities', path: '/vulnerabilities', heading: 'Vulnerabilities' },
  { label: 'License Policy', path: '/license-policy', heading: /license/i },
  { label: 'Docker', path: '/docker', heading: 'Docker Repositories' },
  { label: 'Overrides', path: '/overrides', heading: 'Policy Overrides' },
  { label: 'Audit Log', path: '/audit-log', heading: 'Audit Log' },
  { label: 'Settings', path: '/settings', heading: 'Settings' },
]

// Attach a console-error collector that ignores benign network noise (the open
// dev gate 404s a couple of optional endpoints like /dashboard/stats).
function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = []
  page.on('console', (msg) => {
    if (msg.type() !== 'error') return
    const text = msg.text()
    if (/Failed to load resource|status of 40\d|status of 50\d/i.test(text)) return
    errors.push(text)
  })
  page.on('pageerror', (err) => errors.push(err.message))
  return errors
}

test('root redirects to dashboard', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveURL(/\/dashboard$/)
})

test('sidebar navigates to every page and highlights the active link', async ({ page }) => {
  const errors = collectConsoleErrors(page)
  await page.goto('/dashboard')

  for (const item of NAV) {
    const link = page.getByRole('navigation').getByRole('link', { name: item.label, exact: true })
    await link.click()
    await expect(page).toHaveURL(new RegExp(`${item.path.replace(/\//g, '\\/')}$`))
    // The active NavLink carries the blue background (see Layout.tsx).
    await expect(link).toHaveClass(/bg-blue-600/)
    // The page rendered its heading rather than an error frame.
    await expect(
      page.getByRole('heading', { name: item.heading }).first(),
    ).toBeVisible({ timeout: 10_000 })
    await page.waitForLoadState('networkidle')
  }

  expect(errors, `unexpected console errors: ${errors.join(' | ')}`).toEqual([])
})

test('profile page renders without a crash', async ({ page }) => {
  const errors = collectConsoleErrors(page)
  await page.goto('/profile')
  await expect(page.getByRole('heading', { name: 'Profile' }).first()).toBeVisible()
  expect(errors, `unexpected console errors: ${errors.join(' | ')}`).toEqual([])
})

test('unknown route does not throw', async ({ page }) => {
  // There is no catch-all `*` route, so an unmatched path renders an empty
  // outlet rather than a 404 page. That is acceptable; what must NOT happen is
  // a thrown JS error. Assert the document mounts cleanly without a pageerror.
  const errors: string[] = []
  page.on('pageerror', (err) => errors.push(err.message))
  await page.goto('/this-route-does-not-exist')
  await expect(page.locator('#root')).toBeAttached()
  expect(errors, `unexpected page errors: ${errors.join(' | ')}`).toEqual([])
})
