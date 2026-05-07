export function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// Docker manifest digests are 71 chars (sha256:...) and overflow narrow
// table cells. Show a short prefix; callers should expose the full value via
// a hover tooltip.
export function truncateSha256(value: string, prefixLen = 19): string {
  if (value.startsWith('sha256:') && value.length > prefixLen) {
    return `${value.slice(0, prefixLen)}…`
  }
  return value
}
