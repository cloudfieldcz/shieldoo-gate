# UI Test Suite (visual regression + interaction flows)

The admin UI has a standalone end-to-end test suite under [`ui/e2e/`](../../ui/e2e),
driven by [Playwright](https://playwright.dev). It covers two things:

1. **Visual regression** — a full-page screenshot of every top-level page in its
   empty/default state, diffed against a committed baseline. Catches silent
   layout/style breakage (e.g. the React 19 / Tailwind 4 upgrade).
2. **Interaction flows** — sidebar navigation across every page, the active-link
   highlight, the root redirect, a console-error guard, and the richer
   functional flows (license badge, typosquat override, vuln-scan lifecycle).

## Why it is separate from the shell e2e

This suite is **intentionally decoupled** from the shell e2e harness
([`tests/e2e-shell/run_all.sh`](e2e-testing.md)). The shell suite leaves the
gate's database full of arbitrary artifacts, scans, and timestamps — which would
make screenshots flap. The UI suite instead brings up its **own fresh,
open-mode (no-auth) gate with an empty DB**, so the rendered pages are
deterministic by construction. The two suites share only the gate Docker image,
never a database.

## Determinism

Visual baselines are only stable if rendering is reproducible:

- **Pinned browser environment.** Baselines are generated and verified inside
  the pinned `mcr.microsoft.com/playwright` container (digest-pinned in
  [`tests/ui-e2e/run.sh`](../../tests/ui-e2e/run.sh)), whose tag matches the
  `@playwright/test` version in [`ui/package.json`](../../ui/package.json). This
  is what keeps a baseline generated on a macOS laptop byte-identical to the one
  CI compares against on Linux — **never** run `--update-snapshots` outside this
  container.
- **Pinned rendering inputs.** [`playwright.config.ts`](../../ui/playwright.config.ts)
  fixes the viewport (1280×800), device scale, `colorScheme: light`,
  `timezoneId: UTC`, and `locale: en-US`, and disables animations/caret.
- **Masking.** Genuinely volatile regions are masked (rendered as solid blocks
  that do not participate in the diff) by [`e2e/support/visual.ts`](../../ui/e2e/support/visual.ts):
  the header (identity), the sidebar footer (build version), the sidebar vuln
  badge (live count), and all charts (time-relative axes). Per-page volatile
  regions — e.g. the audit log's timestamped rows and event counter — are masked
  in the spec.

## Empty vs seeded views

Empty-state pages need no data. The data-driven detail pages
(`/projects/:id`, `/vulnerabilities/components/:id`, `/vulnerabilities/scan-runs/:id`,
`/docker/repositories/:id`) and the functional flows require seeded data and a
`scan:upload`-scoped token. When `SGW_PROXY_TOKEN` is set, the global setup
([`e2e/support/seed.ts`](../../ui/e2e/support/seed.ts)) pushes a known SBOM and
those specs run; without it they **self-skip** rather than fail. The default CI
run is token-less (empty-state visual + flow coverage only).

## Running

```bash
# Verify against committed baselines (builds + boots a fresh gate, runs the
# suite in the pinned container, tears the gate down):
make test-ui

# Regenerate baselines after an INTENTIONAL UI change, then review the diff
# in git before committing:
make test-ui-update

# Leave the gate running for debugging:
bash tests/ui-e2e/run.sh --keep
```

Baselines live in `ui/e2e/__screenshots__/` and **are committed**. A failing
visual test in CI uploads the Playwright HTML report (diff images + traces) as a
`playwright-report` artifact.

## CI

The [`ui-e2e` job in `ci.yml`](ci.md) runs `make test-ui` on every pull request,
in parallel with the Go and UI lint/build jobs.

## Adding a page

1. Add a `PageCase` entry to [`e2e/visual/pages.spec.ts`](../../ui/e2e/visual/pages.spec.ts)
   (with `maskSelectors` for any volatile body regions) and a `NAV` entry to
   [`e2e/flows/navigation.spec.ts`](../../ui/e2e/flows/navigation.spec.ts).
2. Run `make test-ui-update` to generate the baseline.
3. Eyeball the new PNG under `ui/e2e/__screenshots__/` before committing.
