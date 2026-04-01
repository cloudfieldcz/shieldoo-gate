import type { ArtifactWithStatus } from '../api/types'
import StatusBadge from './StatusBadge'

interface ArtifactTableProps {
  artifacts: ArtifactWithStatus[]
  onRowClick: (artifact: ArtifactWithStatus) => void
  selectedId?: string
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
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
            {['Ecosystem', 'Name', 'Version', 'Status', 'Size', 'Cached At'].map((col) => (
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
              <td className="px-4 py-3 text-sm text-gray-600 font-mono">{a.version}</td>
              <td className="px-4 py-3 text-sm">
                <StatusBadge status={a.status.status} />
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
