import { request as playwrightRequest } from '@playwright/test'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'

// Deterministic seed state shared between globalSetup and the specs.
// Written to e2e/.seed-state.json (git-ignored). Specs read it to decide
// whether the seeded detail-page views are reachable.
export interface SeedState {
  seeded: boolean
  vulnComponentId?: number
  vulnScanRunId?: number
}

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const SEED_STATE_PATH = path.join(__dirname, '..', '.seed-state.json')
const SBOM_VULN = path.join(__dirname, '..', 'fixtures', 'sbom-vulnerable.json')

export function readSeedState(): SeedState {
  try {
    return JSON.parse(fs.readFileSync(SEED_STATE_PATH, 'utf-8')) as SeedState
  } catch {
    return { seeded: false }
  }
}

// globalSetup: when a scan:upload-scoped token is available (SGW_PROXY_TOKEN),
// push one known-vulnerable SBOM so the vulnerability detail pages render real
// data. Without a token the scans endpoint is gated (403) — we record
// seeded:false and the seeded specs self-skip, exactly like the legacy
// vuln-scan.spec. Visual snapshots of EMPTY-state pages need no seed at all.
export default async function globalSetup(): Promise<void> {
  const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:8080'
  const token = process.env.SGW_PROXY_TOKEN ?? ''
  const state: SeedState = { seeded: false }

  if (!token) {
    fs.writeFileSync(SEED_STATE_PATH, JSON.stringify(state, null, 2))
    return
  }

  const ctx = await playwrightRequest.newContext({
    extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    ignoreHTTPSErrors: true,
  })
  try {
    const body = fs.readFileSync(SBOM_VULN)
    const resp = await ctx.post(
      `${baseURL}/api/v1/projects/default/components/ui-e2e-seed/scans?ecosystem=multi`,
      {
        headers: { 'Content-Type': 'application/vnd.cyclonedx+json' },
        data: body,
      },
    )
    if (resp.ok()) {
      const j = (await resp.json()) as { component_id?: number; scan_run_id?: number }
      state.seeded = true
      state.vulnComponentId = j.component_id
      state.vulnScanRunId = j.scan_run_id
    } else {
      // Non-fatal: leave seeded:false so specs skip rather than fail the run.
      console.warn(`ui-e2e seed: scan upload returned ${resp.status()}; seeded views will skip`)
    }
  } finally {
    await ctx.dispose()
  }

  fs.writeFileSync(SEED_STATE_PATH, JSON.stringify(state, null, 2))
}
