/**
 * Parses an artifact ID string into its components.
 * Format: "ecosystem:name:version" or "ecosystem:name:version:filename"
 */
export function parseArtifactId(id: string | undefined | null): { ecosystem: string; name: string; version: string } | null {
  if (!id) return null
  const parts = id.split(':')
  if (parts.length < 3) return null
  return {
    ecosystem: parts[0],
    name: parts[1],
    version: parts[2],
  }
}

/**
 * Extracts a search-friendly name from a potentially sanitized package name.
 * npm adapter sanitizes "@scope/pkg" to "scope_pkg" in artifact IDs/overrides,
 * but the artifacts table stores the original name. Use the last segments
 * as a substring search term so the LIKE filter matches.
 */
function searchName(name: string): string {
  // If name contains / or @, it's already in original form
  if (name.includes('/') || name.includes('@')) return name
  // For sanitized names like "alloc_quick_lru", use last 2 segments
  const segments = name.split('_')
  return segments.length > 2 ? segments.slice(-2).join('_') : name
}

export function buildArtifactLink(artifactId: string | undefined | null): string | null {
  const parsed = parseArtifactId(artifactId)
  if (!parsed) return null
  const params = new URLSearchParams()
  params.set('ecosystem', parsed.ecosystem)
  params.set('name', searchName(parsed.name))
  if (parsed.version) params.set('version', parsed.version)
  return `/artifacts?${params.toString()}`
}

/**
 * Builds a link to the artifacts page from override fields.
 */
export function buildOverrideArtifactLink(ecosystem: string, name: string, version?: string): string {
  const params = new URLSearchParams()
  params.set('ecosystem', ecosystem)
  params.set('name', searchName(name))
  if (version) params.set('version', version)
  return `/artifacts?${params.toString()}`
}
