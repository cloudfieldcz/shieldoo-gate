import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { overridesApi } from '../api/client'
import type { PolicyOverride } from '../api/types'
import { Trash2, ChevronLeft, ChevronRight } from 'lucide-react'

const PER_PAGE = 20

function scopeLabel(scope: string) {
  return scope === 'package' ? 'All versions' : 'Exact version'
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

export default function Overrides() {
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const [activeOnly, setActiveOnly] = useState(true)

  const listQuery = useQuery({
    queryKey: ['overrides', page, activeOnly],
    queryFn: () => overridesApi.list(page, PER_PAGE, activeOnly || undefined),
    retry: 1,
  })

  const revokeMutation = useMutation({
    mutationFn: (id: number) => overridesApi.revoke(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['overrides'] })
    },
  })

  const overrides = listQuery.data?.data ?? []
  const total = listQuery.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  return (
    <div className="p-8 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Policy Overrides</h1>
        <p className="text-sm text-gray-500 mt-1">Manage false-positive exceptions for blocked artifacts</p>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-gray-700">
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={(e) => { setActiveOnly(e.target.checked); setPage(1) }}
            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          />
          Active only
        </label>
        <span className="text-sm text-gray-500 ml-auto">
          {listQuery.isLoading ? 'Loading...' : `${total} override${total !== 1 ? 's' : ''}`}
        </span>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        {listQuery.isError ? (
          <div className="p-8 text-center text-red-500 text-sm">
            Failed to load overrides. Is the API server running?
          </div>
        ) : (
          <table className="w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Package</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scope</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Reason</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {overrides.map((o: PolicyOverride) => (
                <tr key={o.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-sm">
                    <span className="font-mono text-gray-800">{o.ecosystem}/{o.name}</span>
                    {o.version && (
                      <span className="font-mono text-gray-500 ml-1">@{o.version}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">{scopeLabel(o.scope)}</td>
                  <td className="px-4 py-3 text-sm text-gray-600 max-w-xs truncate">{o.reason || '—'}</td>
                  <td className="px-4 py-3 text-sm text-gray-500">{formatDate(o.created_at)}</td>
                  <td className="px-4 py-3 text-sm">
                    {o.revoked ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                        Revoked
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700">
                        Active
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {!o.revoked && (
                      <button
                        onClick={() => revokeMutation.mutate(o.id)}
                        disabled={revokeMutation.isPending}
                        className="inline-flex items-center gap-1 px-2 py-1 text-xs font-medium rounded border border-red-200 text-red-600 hover:bg-red-50 disabled:opacity-50"
                        title="Revoke this override"
                      >
                        <Trash2 className="w-3 h-3" />
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {overrides.length === 0 && !listQuery.isLoading && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-sm text-gray-400">
                    No overrides found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
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
