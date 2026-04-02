import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { auditApi } from '../api/client'
import { buildArtifactLink } from '../utils/artifactId'
import { ChevronLeft, ChevronRight } from 'lucide-react'

const EVENT_TYPES = [
  '',
  'SERVED',
  'BLOCKED',
  'QUARANTINED',
  'RELEASED',
  'SCANNED',
]

const PER_PAGE = 50

const eventTypeBadge: Record<string, string> = {
  SERVED: 'bg-green-100 text-green-800',
  BLOCKED: 'bg-red-100 text-red-800',
  QUARANTINED: 'bg-orange-100 text-orange-800',
  RELEASED: 'bg-blue-100 text-blue-800',
  SCANNED: 'bg-gray-100 text-gray-700',
}

function formatDate(iso: string) {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export default function AuditLog() {
  const [page, setPage] = useState(1)
  const [eventType, setEventType] = useState('')

  const query = useQuery({
    queryKey: ['audit', page, eventType],
    queryFn: () => auditApi.list(page, PER_PAGE, eventType || undefined),
    retry: 1,
  })

  const entries = query.data?.data ?? []
  const total = query.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  function handleFilterChange() {
    setPage(1)
  }

  return (
    <div className="p-8 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
        <p className="text-sm text-gray-500 mt-1">Append-only record of all security events</p>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={eventType}
          onChange={(e) => { setEventType(e.target.value); handleFilterChange() }}
        >
          <option value="">All Event Types</option>
          {EVENT_TYPES.filter(Boolean).map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        <span className="text-sm text-gray-500 ml-auto">
          {query.isLoading ? 'Loading...' : `${total} event${total !== 1 ? 's' : ''}`}
        </span>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        {query.isError ? (
          <div className="p-8 text-center text-red-500 text-sm">
            Failed to load audit log. Is the API server running?
          </div>
        ) : entries.length === 0 && !query.isLoading ? (
          <div className="p-8 text-center text-gray-400 text-sm">
            No audit events found.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {['Timestamp', 'Event Type', 'Artifact ID', 'Actor', 'Reason'].map((col) => (
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
                {entries.map((entry) => (
                  <tr key={entry.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 text-sm text-gray-600 whitespace-nowrap">
                      {formatDate(entry.ts)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span
                        className={`inline-block text-xs font-medium px-2 py-0.5 rounded ${
                          eventTypeBadge[entry.event_type] ?? 'bg-gray-100 text-gray-700'
                        }`}
                      >
                        {entry.event_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm font-mono max-w-xs truncate">
                      {entry.artifact_id ? (
                        (() => {
                          const link = buildArtifactLink(entry.artifact_id)
                          return link ? (
                            <Link to={link} className="text-blue-600 hover:text-blue-800 hover:underline" title={entry.artifact_id}>
                              {entry.artifact_id}
                            </Link>
                          ) : (
                            <span className="text-gray-700">{entry.artifact_id}</span>
                          )
                        })()
                      ) : (
                        <span className="text-gray-300">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600">
                      {entry.user_email ? (
                        <span>{entry.user_email}</span>
                      ) : entry.client_ip ? (
                        <span className="font-mono">{entry.client_ip}</span>
                      ) : (
                        <span className="italic text-gray-400">system</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 max-w-xs truncate">
                      {entry.reason ?? <span className="text-gray-300">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="flex items-center gap-1 text-sm text-gray-600 disabled:opacity-40 hover:text-blue-600"
            >
              <ChevronLeft className="w-4 h-4" /> Previous
            </button>
            <span className="text-sm text-gray-500">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="flex items-center gap-1 text-sm text-gray-600 disabled:opacity-40 hover:text-blue-600"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
