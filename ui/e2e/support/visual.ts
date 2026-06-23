import { expect, type Page, type Locator } from '@playwright/test'

// Regions whose content is environment- or time-dependent and therefore must
// never participate in a visual diff:
//   - header (UserMenu): shows the logged-in identity, which differs by auth mode
//   - sidebar footer: renders the build version (`v<APP_VERSION>`)
//   - sidebar vuln badge: a live count that changes with seeded data
// Anything genuinely volatile inside a page body (timestamps, ids, durations)
// is masked per-spec via the `extraMasks` argument.
export function chromeMasks(page: Page): Locator[] {
  return [
    page.locator('header'),
    page.locator('aside div.border-t'),
    page.getByRole('navigation').locator('span.rounded-full'),
    // Charts (recharts) plot time-relative axes (e.g. the dashboard's last-7-days
    // traffic graph), so their pixels drift daily. Mask the plot area everywhere;
    // a layout shift around the chart is still caught because the mask box moves
    // with it. Resolves to nothing on chart-less pages.
    page.locator('.recharts-responsive-container'),
  ]
}

// Navigate to a route and wait until the data-driven page has settled: network
// idle (React Query fetches resolved) plus a short paint settle so spinners are
// gone before the shot. Returns once the layout is stable.
export async function gotoStable(page: Page, route: string): Promise<void> {
  await page.goto(route)
  await page.waitForLoadState('networkidle')
  // Fonts must be ready or glyph metrics shift between runs.
  await page.evaluate(() => document.fonts.ready)
  await page.waitForTimeout(250)
}

// Full-page visual assertion with the volatile chrome masked. `name` is the
// baseline file stem (e.g. 'dashboard.png'); `extraMasks` adds page-specific
// volatile regions (a table body of timestamped rows, etc.).
export async function stableShot(
  page: Page,
  name: string,
  extraMasks: Locator[] = [],
): Promise<void> {
  await expect(page).toHaveScreenshot(name, {
    fullPage: true,
    mask: [...chromeMasks(page), ...extraMasks],
  })
}
