import type { ArtifactWithStatus } from '../api/types'
import StatusBadge from './StatusBadge'
import { ShieldAlert } from 'lucide-react'
import { formatDate, formatBytes } from '../utils/format'

interface ArtifactTableProps {
  artifacts: ArtifactWithStatus[]
  onRowClick: (artifact: ArtifactWithStatus) => void
  selectedId?: string
}

// Some ecosystems (notably docker images) carry hundreds of bundled-component
// licenses. Showing them all inline blows up row height and hides every other
// row off-screen. Cap at MAX_VISIBLE_LICENSES with a "+N" tooltip overflow.
const MAX_VISIBLE_LICENSES = 4

// Docker manifest digests in the version column are 71 chars (sha256:...) —
// they overflow the cell and waste space. Show a short prefix; full value
// stays available via hover tooltip.
function formatVersion(version: string): string {
  if (version === '*') return ''
  if (version.startsWith('sha256:') && version.length > 19) {
    return `${version.slice(0, 19)}…`
  }
  return version
}

export default function ArtifactTable({ artifacts, onRowClick, selectedId }: ArtifactTableProps) {
  if (artifacts.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 text-sm">
        No artifacts found.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200">
        <thead className="bg-gray-50">
          <tr>
            {['Ecosystem', 'Name', 'Version', 'Licenses', 'Status', 'Size', 'Cached At'].map((col) => (
              <th
                key={col}
                className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-100">
          {artifacts.map((a) => (
            <tr
              key={a.id}
              onClick={() => onRowClick(a)}
              className={`cursor-pointer transition-colors hover:bg-blue-50 ${
                selectedId === a.id ? 'bg-blue-50 ring-1 ring-inset ring-blue-200' : ''
              }`}
            >
              <td className="px-4 py-3 text-sm">
                <span className="inline-block bg-gray-100 text-gray-700 text-xs font-mono px-2 py-0.5 rounded">
                  {a.ecosystem}
                </span>
              </td>
              <td className="px-4 py-3 text-sm max-w-xs">
                <div className="font-medium text-gray-900 truncate">{a.name}</div>
                {a.id.split(':').length >= 4 && (
                  <div className="text-xs text-gray-400 font-mono truncate" title={a.id.split(':').slice(3).join(':')}>
                    {a.id.split(':').slice(3).join(':')}
                  </div>
                )}
              </td>
              <td className="px-4 py-3 text-sm text-gray-600 font-mono whitespace-nowrap">
                {a.version === '*' ? (
                  <span className="italic text-gray-500">(any version)</span>
                ) : (
                  <span title={a.version}>{formatVersion(a.version)}</span>
                )}
              </td>
              <td className="px-4 py-3 text-sm">
                {a.licenses?.length ? (
                  <div className="flex flex-wrap gap-1 items-center">
                    {a.licenses.slice(0, MAX_VISIBLE_LICENSES).map((l) => (
                      <span
                        key={l}
                        className="inline-block px-1.5 py-0.5 rounded text-xs font-mono bg-blue-50 text-blue-700 border border-blue-200"
                      >
                        {l}
                      </span>
                    ))}
                    {a.licenses.length > MAX_VISIBLE_LICENSES && (
                      <span
                        className="inline-block px-1.5 py-0.5 rounded text-xs font-mono bg-gray-100 text-gray-600 border border-gray-200 cursor-help"
                        title={a.licenses.slice(MAX_VISIBLE_LICENSES).join(', ')}
                      >
                        +{a.licenses.length - MAX_VISIBLE_LICENSES}
                      </span>
                    )}
                  </div>
                ) : (
                  <span className="text-xs text-gray-300">—</span>
                )}
              </td>
              <td className="px-4 py-3 text-sm">
                <div className="flex items-center gap-1.5">
                  <StatusBadge status={a.status.status} />
                  {a.has_override && (
                    <span title="Active policy override">
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                    </span>
                  )}
                </div>
              </td>
              <td className="px-4 py-3 text-sm text-gray-500">{formatBytes(a.size_bytes)}</td>
              <td className="px-4 py-3 text-sm text-gray-500">{formatDate(a.cached_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
