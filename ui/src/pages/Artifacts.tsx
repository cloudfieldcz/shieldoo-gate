import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { artifactsApi } from '../api/client'
import type { ArtifactWithStatus } from '../api/types'
import ArtifactTable from '../components/ArtifactTable'
import StatusBadge from '../components/StatusBadge'
import ScanResultCard from '../components/ScanResultCard'
import { X, RefreshCw, ShieldX, ShieldCheck, ShieldAlert, ChevronLeft, ChevronRight } from 'lucide-react'

const ECOSYSTEMS = ['', 'docker', 'pypi', 'npm', 'nuget']
const STATUSES = ['', 'CLEAN', 'SUSPICIOUS', 'QUARANTINED', 'PENDING_SCAN']
const PER_PAGE = 20

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function Artifacts() {
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [ecosystem, setEcosystem] = useState('')
  const [status, setStatus] = useState('')
  const [selected, setSelected] = useState<ArtifactWithStatus | null>(null)

  const listQuery = useQuery({
    queryKey: ['artifacts', page, ecosystem, status],
    queryFn: () => artifactsApi.list(page, PER_PAGE, ecosystem || undefined, status || undefined),
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
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', selected?.id] })
    },
  })

  const overrideMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.override(id, { reason: 'false positive', scope: 'version' }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', selected?.id] })
    },
  })

  const artifacts = listQuery.data?.data ?? []
  const total = listQuery.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))
  const detail = detailQuery.data

  function handleFilterChange() {
    setPage(1)
    setSelected(null)
  }

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
          onChange={(e) => { setEcosystem(e.target.value); handleFilterChange() }}
        >
          <option value="">All Ecosystems</option>
          {ECOSYSTEMS.filter(Boolean).map((e) => (
            <option key={e} value={e}>{e}</option>
          ))}
        </select>

        <select
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={status}
          onChange={(e) => { setStatus(e.target.value); handleFilterChange() }}
        >
          <option value="">All Statuses</option>
          {STATUSES.filter(Boolean).map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

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

                {(selected.status.status === 'QUARANTINED' || selected.status.status === 'SUSPICIOUS') && (
                  <button
                    onClick={() => overrideMutation.mutate(selected.id)}
                    disabled={overrideMutation.isPending}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-amber-300 text-amber-700 hover:bg-amber-50 disabled:opacity-50"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    False Positive
                  </button>
                )}
              </div>

              {/* Scan results */}
              <div className="pt-2 border-t border-gray-100">
                <h3 className="text-xs font-semibold text-gray-700 uppercase tracking-wider mb-3">
                  Scan History
                </h3>
                {detailQuery.isLoading ? (
                  <p className="text-sm text-gray-400">Loading scan results...</p>
                ) : detail?.scan_results?.length ? (
                  <div className="space-y-3">
                    {detail.scan_results.map((r) => (
                      <ScanResultCard key={r.id} result={r} />
                    ))}
                  </div>
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
