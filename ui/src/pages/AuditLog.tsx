import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { auditApi } from '../api/client'
import type { AuditEntry, AuditMetadata } from '../api/types'
import ArtifactDetailPanel from '../components/ArtifactDetailPanel'
import { ChevronLeft, ChevronRight, RefreshCw, Brain, ChevronDown, ChevronUp } from 'lucide-react'
import { formatDate } from '../utils/format'

type TabId = 'all' | 'allowed_with_warning'

const TABS: { id: TabId; label: string; eventType?: string }[] = [
  { id: 'all', label: 'All Events' },
  { id: 'allowed_with_warning', label: 'Allowed with Warnings', eventType: 'ALLOWED_WITH_WARNING' },
]

const EVENT_TYPES = [
  '',
  'SERVED',
  'BLOCKED',
  'QUARANTINED',
  'RELEASED',
  'SCANNED',
  'ALLOWED_WITH_WARNING',
]

const PER_PAGE = 50

const eventTypeBadge: Record<string, string> = {
  SERVED: 'bg-green-100 text-green-800',
  BLOCKED: 'bg-red-100 text-red-800',
  QUARANTINED: 'bg-orange-100 text-orange-800',
  RELEASED: 'bg-blue-100 text-blue-800',
  SCANNED: 'bg-gray-100 text-gray-700',
  ALLOWED_WITH_WARNING: 'bg-amber-100 text-amber-800',
}

function parseMetadata(json?: string): AuditMetadata | null {
  if (!json) return null
  try {
    return JSON.parse(json) as AuditMetadata
  } catch {
    return null
  }
}

function TriageExplanation({ entry }: { entry: AuditEntry }) {
  const [expanded, setExpanded] = useState(false)
  const metadata = parseMetadata(entry.metadata_json)
  const triage = metadata?.ai_triage

  if (!triage) return null

  return (
    <div className="mt-2">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-1.5 text-xs text-purple-600 hover:text-purple-800"
      >
        <Brain className="w-3.5 h-3.5" />
        AI Triage: {triage.decision}
        {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
      </button>
      {expanded && (
        <div className="mt-2 bg-purple-50 border border-purple-200 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
              triage.decision === 'ALLOW'
                ? 'bg-green-100 text-green-800'
                : 'bg-red-100 text-red-800'
            }`}>
              {triage.decision}
            </span>
            <span className="text-xs text-purple-600">
              Confidence: {Math.round(triage.confidence * 100)}%
            </span>
          </div>
          {triage.explanation && (
            <p className="text-sm text-purple-900 leading-relaxed">
              {triage.explanation}
            </p>
          )}
          <div className="flex flex-wrap gap-3 text-xs text-purple-500">
            {triage.model_used && <span>Model: {triage.model_used}</span>}
            {triage.tokens_used > 0 && <span>Tokens: {triage.tokens_used}</span>}
            {triage.cache_hit && <span className="text-purple-400">(cached)</span>}
          </div>
        </div>
      )}
    </div>
  )
}

export default function AuditLog() {
  const [activeTab, setActiveTab] = useState<TabId>('all')
  const [page, setPage] = useState(1)
  const [eventType, setEventType] = useState('')
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null)

  // Determine the effective event_type filter: tab override or dropdown selection.
  const tabConfig = TABS.find((t) => t.id === activeTab)!
  const effectiveEventType = tabConfig.eventType ?? (eventType || undefined)

  const query = useQuery({
    queryKey: ['audit', page, activeTab, eventType],
    queryFn: () => auditApi.list(page, PER_PAGE, effectiveEventType),
    retry: 1,
  })

  const entries = query.data?.data ?? []
  const total = query.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  function handleTabChange(tab: TabId) {
    setActiveTab(tab)
    setPage(1)
    setEventType('')
  }

  return (
    <div className="p-8 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
        <p className="text-sm text-gray-500 mt-1">Append-only record of all security events</p>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex gap-6" aria-label="Tabs">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => handleTabChange(tab.id)}
              className={`pb-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Filter bar (only show dropdown when on "All Events" tab) */}
      <div className="flex flex-wrap gap-3 items-center">
        {activeTab === 'all' && (
          <select
            className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={eventType}
            onChange={(e) => { setEventType(e.target.value); setPage(1) }}
          >
            <option value="">All Event Types</option>
            {EVENT_TYPES.filter(Boolean).map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        )}

        <span className="text-sm text-gray-500 ml-auto flex items-center gap-2">
          {query.isLoading ? 'Loading...' : `${total} event${total !== 1 ? 's' : ''}`}
          <button
            onClick={() => query.refetch()}
            disabled={query.isFetching}
            className="p-1 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-100 disabled:opacity-50 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${query.isFetching ? 'animate-spin' : ''}`} />
          </button>
        </span>
      </div>

      {/* Main content: table + detail panel */}
      <div className={`flex gap-4 ${selectedArtifactId ? 'items-start' : ''}`}>
        {/* Table */}
        <div className={`bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden ${selectedArtifactId ? 'flex-1 min-w-0' : 'w-full'}`}>
          {query.isError ? (
            <div className="p-8 text-center text-red-500 text-sm">
              Failed to load audit log. Is the API server running?
            </div>
          ) : entries.length === 0 && !query.isLoading ? (
            <div className="p-8 text-center text-gray-400 text-sm">
              {activeTab === 'allowed_with_warning'
                ? 'No allowed-with-warning events found. These appear when the policy mode allows suspicious artifacts through with a warning.'
                : 'No audit events found.'}
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
                          <button
                            onClick={() => setSelectedArtifactId(
                              selectedArtifactId === entry.artifact_id ? null : entry.artifact_id!
                            )}
                            className={`text-left hover:underline truncate block max-w-xs ${
                              selectedArtifactId === entry.artifact_id
                                ? 'text-blue-800 font-semibold'
                                : 'text-blue-600 hover:text-blue-800'
                            }`}
                            title={entry.artifact_id}
                          >
                            {entry.artifact_id}
                          </button>
                        ) : (
                          <span className="text-gray-300">&mdash;</span>
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
                      <td className="px-4 py-3 text-sm text-gray-600 max-w-sm">
                        <div className="truncate">
                          {entry.reason ?? <span className="text-gray-300">&mdash;</span>}
                        </div>
                        <TriageExplanation entry={entry} />
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

        {/* Detail panel */}
        {selectedArtifactId && (
          <ArtifactDetailPanel
            artifactId={selectedArtifactId}
            onClose={() => setSelectedArtifactId(null)}
          />
        )}
      </div>
    </div>
  )
}
