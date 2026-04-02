/**
 * Parses an artifact ID string into its components.
 * Format: "ecosystem:name:version" or "ecosystem:name:version:filename"
 * Handles scoped npm packages like "npm:@scope/pkg:1.0.0"
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

export function buildArtifactLink(artifactId: string | undefined | null): string | null {
  const parsed = parseArtifactId(artifactId)
  if (!parsed) return null
  const params = new URLSearchParams()
  params.set('ecosystem', parsed.ecosystem)
  params.set('name', parsed.name)
  if (parsed.version) params.set('version', parsed.version)
  return `/artifacts?${params.toString()}`
}
