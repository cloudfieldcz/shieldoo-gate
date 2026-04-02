import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { artifactsApi } from '../api/client'
import StatusBadge from './StatusBadge'
import ScanResultCard from './ScanResultCard'
import { X, RefreshCw, ShieldX, ShieldCheck } from 'lucide-react'

interface ArtifactDetailPanelProps {
  artifactId: string
  onClose: () => void
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function ArtifactDetailPanel({ artifactId, onClose }: ArtifactDetailPanelProps) {
  const qc = useQueryClient()
  const [showScanHistory, setShowScanHistory] = useState(false)

  const detailQuery = useQuery({
    queryKey: ['artifact-detail', artifactId],
    queryFn: () => artifactsApi.get(artifactId),
    retry: 1,
  })

  const rescanMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.rescan(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', artifactId] })
    },
  })

  const quarantineMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.quarantine(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', artifactId] })
    },
  })

  const releaseMutation = useMutation({
    mutationFn: (id: string) => artifactsApi.release(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
      void qc.invalidateQueries({ queryKey: ['artifact-detail', artifactId] })
    },
  })

  const detail = detailQuery.data
  const status = detail?.status?.status

  if (detailQuery.isLoading) {
    return (
      <div className="w-96 flex-shrink-0 bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-400">Loading...</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 text-sm text-gray-400">Loading artifact details...</div>
      </div>
    )
  }

  if (detailQuery.isError || !detail) {
    return (
      <div className="w-96 flex-shrink-0 bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-900 truncate max-w-xs">{artifactId}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 text-sm text-red-500">Failed to load artifact details.</div>
      </div>
    )
  }

  return (
    <div className="w-96 flex-shrink-0 bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
        <h2 className="text-sm font-semibold text-gray-900 truncate max-w-xs">
          {detail.name}
        </h2>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-4 overflow-y-auto max-h-[calc(100vh-16rem)]">
        {/* Metadata */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">Ecosystem</span>
            <span className="font-mono text-gray-800">{detail.ecosystem}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">Version</span>
            <span className="font-mono text-gray-800">{detail.version}</span>
          </div>
          {detail.id.split(':').length >= 4 && (
            <div className="flex justify-between text-sm">
              <span className="text-gray-500">Filename</span>
              <span className="font-mono text-xs text-gray-600 truncate max-w-[180px]" title={detail.id.split(':').slice(3).join(':')}>
                {detail.id.split(':').slice(3).join(':')}
              </span>
            </div>
          )}
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">Size</span>
            <span className="text-gray-800">{formatBytes(detail.size_bytes)}</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">Status</span>
            <StatusBadge status={detail.status.status} />
          </div>
          {detail.status.quarantine_reason && (
            <div className="text-sm">
              <span className="text-gray-500">Reason: </span>
              <span className="text-red-700">{detail.status.quarantine_reason}</span>
            </div>
          )}
          <div className="flex justify-between text-sm">
            <span className="text-gray-500">SHA256</span>
            <span className="font-mono text-xs text-gray-600 truncate max-w-[180px]" title={detail.sha256}>
              {detail.sha256.slice(0, 16)}...
            </span>
          </div>
        </div>

        {/* Active overrides */}
        {detail.active_overrides?.length ? (
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
            onClick={() => rescanMutation.mutate(artifactId)}
            disabled={rescanMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Rescan
          </button>

          {status !== 'QUARANTINED' && (
            <button
              onClick={() => quarantineMutation.mutate(artifactId)}
              disabled={quarantineMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-red-300 text-red-700 hover:bg-red-50 disabled:opacity-50"
            >
              <ShieldX className="w-3.5 h-3.5" />
              Quarantine
            </button>
          )}

          {status === 'QUARANTINED' && (
            <button
              onClick={() => releaseMutation.mutate(artifactId)}
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
          {detail.scan_results?.length ? (
            (() => {
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
  )
}
