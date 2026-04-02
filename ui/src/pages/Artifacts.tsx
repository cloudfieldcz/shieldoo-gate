import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { artifactsApi } from '../api/client'
import type { ArtifactWithStatus } from '../api/types'
import ArtifactTable from '../components/ArtifactTable'
import StatusBadge from '../components/StatusBadge'
import ScanResultCard from '../components/ScanResultCard'
import { X, RefreshCw, ShieldX, ShieldCheck, ChevronLeft, ChevronRight } from 'lucide-react'

const ECOSYSTEMS = [
  { value: 'docker', label: 'Docker' },
  { value: 'pypi', label: 'PyPI' },
  { value: 'npm', label: 'npm' },
  { value: 'nuget', label: 'NuGet' },
  { value: 'maven', label: 'Maven' },
  { value: 'rubygems', label: 'RubyGems' },
  { value: 'go', label: 'Go Modules' },
]
const STATUSES = ['', 'CLEAN', 'SUSPICIOUS', 'QUARANTINED', 'PENDING_SCAN']
const PER_PAGE = 20

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function Artifacts() {
  const qc = useQueryClient()
  const [searchParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const [ecosystem, setEcosystem] = useState(searchParams.get('ecosystem') ?? '')
  const [status, setStatus] = useState('')
  const [name, setName] = useState(searchParams.get('name') ?? '')
  const [version, setVersion] = useState(searchParams.get('version') ?? '')
  const [debouncedName, setDebouncedName] = useState(searchParams.get('name') ?? '')
  const [debouncedVersion, setDebouncedVersion] = useState(searchParams.get('version') ?? '')
  const [selected, setSelected] = useState<ArtifactWithStatus | null>(null)
  const [showScanHistory, setShowScanHistory] = useState(false)

  // Debounce name search (300ms)
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedName(name), 300)
    return () => clearTimeout(timer)
  }, [name])

  // Debounce version search (300ms)
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedVersion(version), 300)
    return () => clearTimeout(timer)
  }, [version])

  // Reset page when any filter changes (using debounced values for text inputs)
  useEffect(() => {
    setPage(1)
    setSelected(null)
  }, [ecosystem, status, debouncedName, debouncedVersion])

  // Reset scan history toggle when artifact selection changes
  useEffect(() => {
    setShowScanHistory(false)
  }, [selected?.id])

  const listQuery = useQuery({
    queryKey: ['artifacts', page, ecosystem, status, debouncedName, debouncedVersion],
    queryFn: () => artifactsApi.list(page, PER_PAGE, ecosystem || undefined, status || undefined, debouncedName || undefined, debouncedVersion || undefined),
    retry: 1,
  })

  const detailQuery = useQuery({
    queryKey: ['artifact-detail', selected?.id],
    queryFn: () => artifactsApi.get(selected!.id),
    enabled: !!selected,
    retry: 1,
  })

  const rescanMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.rescan(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', selected?.id] })
    },
  })

  const quarantineMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.quarantine(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', selected?.id] })
    },
  })

  const releaseMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.release(id),
    onSuccess: () => {
      if (selected) {
        setSelected({ ...selected, status: { ...selected.status, status: 'CLEAN', quarantine_reason: '' } })
      }
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', selected?.id] })
    },
  })

  const artifacts = listQuery.data?.data ?? []
  const total = listQuery.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))
  const detail = detailQuery.data


  return (
    <div className="p-8 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Artifacts</h1>
        <p className="text-sm text-gray-500 mt-1">Browse and manage cached artifacts</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={ecosystem}
          onChange={(e) => setEcosystem(e.target.value)}
        >
          <option value="">All Ecosystems</option>
          {ECOSYSTEMS.map((ecosystemOption) => (
            <option key={ecosystemOption.value} value={ecosystemOption.value}>
              {ecosystemOption.label}
            </option>
          ))}
        </select>

        <select
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">All Statuses</option>
          {STATUSES.filter(Boolean).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <input
          type="text"
          placeholder="Search name..."
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 w-48"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />

        <input
          type="text"
          placeholder="Search version..."
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 w-36"
          value={version}
          onChange={(e) => setVersion(e.target.value)}
        />

        <span className="text-sm text-gray-500 ml-auto">
          {listQuery.isLoading ? 'Loading...' : `${total} artifact${total !== 1 ? 's' : ''}`}
        </span>
      </div>

      {/* Main content: table + detail panel */}
      <div className={`flex gap-4 ${selected ? 'items-start' : ''}`}>
        {/* Table */}
        <div className={`bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden ${selected ? 'flex-1 min-w-0' : 'w-full'}`}>
          {listQuery.isError ? (
            <div className="p-8 text-center text-red-500 text-sm">
              Failed to load artifacts. Is the API server running?
            </div>
          ) : (
            <ArtifactTable
              artifacts={artifacts}
              onRowClick={setSelected}
              selectedId={selected?.id}
            />
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
        {selected && (
          <div className="w-96 flex-shrink-0 bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
              <h2 className="text-sm font-semibold text-gray-900 truncate max-w-xs">
                {selected.name}
              </h2>
              <button
                onClick={() => setSelected(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 space-y-4 overflow-y-auto max-h-[calc(100vh-16rem)]">
              {/* Metadata */}
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Ecosystem</span>
                  <span className="font-mono text-gray-800">{selected.ecosystem}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Version</span>
                  <span className="font-mono text-gray-800">{selected.version}</span>
                </div>
                {selected.id.split(':').length >= 4 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Filename</span>
                    <span className="font-mono text-xs text-gray-600 truncate max-w-[180px]" title={selected.id.split(':').slice(3).join(':')}>
                      {selected.id.split(':').slice(3).join(':')}
                    </span>
                  </div>
                )}
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Size</span>
                  <span className="text-gray-800">{formatBytes(selected.size_bytes)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Status</span>
                  <StatusBadge status={selected.status.status} />
                </div>
                {selected.status.quarantine_reason && (
                  <div className="text-sm">
                    <span className="text-gray-500">Reason: </span>
                    <span className="text-red-700">{selected.status.quarantine_reason}</span>
                  </div>
                )}
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">SHA256</span>
                  <span className="font-mono text-xs text-gray-600 truncate max-w-[180px]" title={selected.sha256}>
                    {selected.sha256.slice(0, 16)}...
                  </span>
                </div>
              </div>

              {/* Active overrides */}
              {detail?.active_overrides?.length ? (
                <div className="bg-amber-50 border border-amber-200 rounded-lg p-3">
                  <h3 className="text-xs font-semibold text-amber-800 uppercase tracking-wider mb-2">
                    Active Override{detail.active_overrides.length > 1 ? 's' : ''}
                  </h3>
                  {detail.active_overrides.map((o) => (
                    <div key={o.id} className="text-sm text-amber-900 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="inline-block bg-amber-100 text-amber-800 text-xs font-medium px-2 py-0.5 rounded">
                          {o.scope === 'package' ? 'All versions' : 'Exact version'}
                        </span>
                        {o.created_by && (
                          <span className="text-xs text-amber-600">by {o.created_by}</span>
                        )}
                      </div>
                      {o.reason && <p className="text-xs text-amber-700">{o.reason}</p>}
                      {o.expires_at && (
                        <p className="text-xs text-amber-600">Expires: {new Date(o.expires_at).toLocaleString()}</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : null}

              {/* Action buttons */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-gray-100">
                <button
                  onClick={() => rescanMutation.mutate(selected.id)}
                  disabled={rescanMutation.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Rescan
                </button>

                {selected.status.status !== 'QUARANTINED' && (
                  <button
                    onClick={() => quarantineMutation.mutate(selected.id)}
                    disabled={quarantineMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-red-300 text-red-700 hover:bg-red-50 disabled:opacity-50"
                  >
                    <ShieldX className="w-3.5 h-3.5" />
                    Quarantine
                  </button>
                )}

                {selected.status.status === 'QUARANTINED' && (
                  <button
                    onClick={() => releaseMutation.mutate(selected.id)}
                    disabled={releaseMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-green-300 text-green-700 hover:bg-green-50 disabled:opacity-50"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    Release
                  </button>
                )}

              </div>

              {/* Scan results */}
              <div className="pt-2 border-t border-gray-100">
                <h3 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">
                  Latest Scans
                </h3>
                {detailQuery.isLoading ? (
                  <p className="text-sm text-gray-400">Loading scan results...</p>
                ) : detail?.scan_results?.length ? (
                  (() => {
                    // Group by scanner: show latest result per scanner, rest is history
                    const latestByScanner = new Map<string, typeof detail.scan_results[0]>()
                    const olderResults: typeof detail.scan_results = []
                    for (const r of detail.scan_results) {
                      if (!latestByScanner.has(r.scanner_name)) {
                        latestByScanner.set(r.scanner_name, r)
                      } else {
                        olderResults.push(r)
                      }
                    }
                    const latestResults = Array.from(latestByScanner.values())
                    return (
                      <div className="space-y-3">
                        {latestResults.map((r) => (
                          <ScanResultCard key={r.id} result={r} />
                        ))}
                        {olderResults.length > 0 && (
                          <>
                            <button
                              onClick={() => setShowScanHistory(!showScanHistory)}
                              className="text-xs text-blue-600 hover:text-blue-800 hover:underline"
                            >
                              {showScanHistory
                                ? 'Hide history'
                                : `Show history (${olderResults.length} older scan${olderResults.length > 1 ? 's' : ''})`}
                            </button>
                            {showScanHistory && (
                              <div className="space-y-3">
                                {olderResults.map((r) => (
                                  <ScanResultCard key={r.id} result={r} />
                                ))}
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    )
                  })()
                ) : (
                  <p className="text-sm text-gray-400">No scan results yet.</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
