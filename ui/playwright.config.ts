import { defineConfig } from '@playwright/test'

// Standalone UI test suite for the Shieldoo Gate admin UI.
//
// This suite is INTENTIONALLY decoupled from the shell e2e harness
// (tests/e2e-shell/run_all.sh). It runs against its own freshly-brought-up,
// deterministically-seeded gate so visual-regression snapshots are stable —
// the shell suite leaves the DB full of arbitrary artifacts/timestamps, which
// would make screenshots flap. See docs/development/ui-e2e.md.
//
// baseURL is env-driven: locally `http://localhost:8080` (docker compose), in
// CI / the pinned-container baseline workflow `http://shieldoo-gate:8080`
// (compose service DNS). SGW_PROXY_TOKEN, when present, unlocks the seed step
// and the token-gated specs; without it those self-skip.
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:8080'

export default defineConfig({
  testDir: './e2e',
  // Baselines live next to the suite, keyed by spec path + the (single,
  // pinned) browser project, so the only rendering environment that can write
  // them is the pinned Playwright container — keeping dev and CI byte-identical.
  snapshotPathTemplate: '{testDir}/__screenshots__/{testFilePath}/{arg}{ext}',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  timeout: 30_000,
  expect: {
    // Small tolerance absorbs sub-pixel antialiasing noise; volatile regions
    // (timestamps, counts, ids) are masked explicitly in stableShot(), not
    // papered over by a large ratio.
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.02,
      animations: 'disabled',
      caret: 'hide',
      scale: 'css',
    },
  },
  use: {
    baseURL: BASE_URL,
    headless: true,
    ignoreHTTPSErrors: true,
    // Pin everything that affects layout/rendering so snapshots are reproducible.
    viewport: { width: 1280, height: 800 },
    deviceScaleFactor: 1,
    colorScheme: 'light',
    timezoneId: 'UTC',
    locale: 'en-US',
    screenshot: 'only-on-failure',
    trace: process.env.CI ? 'retain-on-failure' : 'off',
  },
  globalSetup: './e2e/support/seed.ts',
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
})
