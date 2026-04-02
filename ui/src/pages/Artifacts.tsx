import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { artifactsApi } from '../api/client'
import type { ArtifactWithStatus } from '../api/types'
import ArtifactTable from '../components/ArtifactTable'
import ArtifactDetailPanel from '../components/ArtifactDetailPanel'
import { ChevronLeft, ChevronRight } from 'lucide-react'

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

export default function Artifacts() {
  const [searchParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const [ecosystem, setEcosystem] = useState(searchParams.get('ecosystem') ?? '')
  const [status, setStatus] = useState('')
  const [name, setName] = useState(searchParams.get('name') ?? '')
  const [version, setVersion] = useState(searchParams.get('version') ?? '')
  const [debouncedName, setDebouncedName] = useState(searchParams.get('name') ?? '')
  const [debouncedVersion, setDebouncedVersion] = useState(searchParams.get('version') ?? '')
  const [selected, setSelected] = useState<ArtifactWithStatus | null>(null)

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

  const listQuery = useQuery({
    queryKey: ['artifacts', page, ecosystem, status, debouncedName, debouncedVersion],
    queryFn: () => artifactsApi.list(page, PER_PAGE, ecosystem || undefined, status || undefined, debouncedName || undefined, debouncedVersion || undefined),
    retry: 1,
  })

  const artifacts = listQuery.data?.data ?? []
  const total = listQuery.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))


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
          <ArtifactDetailPanel
            artifactId={selected.id}
            onClose={() => setSelected(null)}
          />
        )}
      </div>
    </div>
  )
}
