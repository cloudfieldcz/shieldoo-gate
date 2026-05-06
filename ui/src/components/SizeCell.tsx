import type { ReactElement } from 'react'
import { formatBytes } from '../utils/format'

/**
 * SizeCellInput is the minimum subset of an artifact needed to render a Size
 * cell. Both ArtifactWithStatus and the Cached Manifests row shape satisfy
 * this — keeping the input narrow lets us reuse this in places that don't
 * carry the full status/override/license fields.
 */
export interface SizeCellInput {
  ecosystem: string
  size_bytes: number
  image_size_bytes?: number
  is_index?: boolean
  is_attestation?: boolean
}

/**
 * Cell-rendering rules per docs/plans/2026-05-06-docker-image-size.md.
 *
 *  is_attestation  is_index   image_size_bytes   render
 *  true            —          —                  "attestation" muted badge (no size)
 *  —               true       —                  "multi-arch" badge (no size)
 *  —               false      non-null           formatBytes(image_size_bytes)
 *  —               false      null               formatBytes(size_bytes)  [fallback]
 *  ecosystem≠docker —         —                  formatBytes(size_bytes)
 */
export function renderSizeCell(a: SizeCellInput): ReactElement {
  if (a.ecosystem !== 'docker') {
    return <span>{formatBytes(a.size_bytes)}</span>
  }
  if (a.is_attestation) {
    return (
      <span
        className="inline-flex items-center px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 text-xs font-medium border border-gray-200"
        title="BuildKit attestation manifest. Carries SBOM/provenance metadata, not a real image."
      >
        attestation
      </span>
    )
  }
  if (a.is_index) {
    return (
      <span
        className="inline-flex items-center px-1.5 py-0.5 rounded bg-purple-50 text-purple-700 text-xs font-medium border border-purple-200"
        title="Multi-arch index. Each platform-specific manifest pulled separately has its own size."
      >
        multi-arch
      </span>
    )
  }
  if (typeof a.image_size_bytes === 'number') {
    return <span>{formatBytes(a.image_size_bytes)}</span>
  }
  // Fallback for not-yet-backfilled or parse-failed rows: show manifest size.
  return <span>{formatBytes(a.size_bytes)}</span>
}
