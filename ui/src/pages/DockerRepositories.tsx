import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { RefreshCw, ExternalLink } from 'lucide-react'
import { dockerApi } from '../api/client'

export default function DockerRepositories() {
  const qc = useQueryClient()
  const [registry, setRegistry] = useState('')

  const reposQuery = useQuery({
    queryKey: ['docker-repositories', registry],
    queryFn: () => dockerApi.listRepositories(registry || undefined),
    retry: 1,
  })

  const registriesQuery = useQuery({
    queryKey: ['docker-registries'],
    queryFn: () => dockerApi.listRegistries(),
    retry: 1,
  })

  const syncMutation = useMutation({
    mutationFn: (repoId: number) => dockerApi.triggerSync(repoId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['docker-repositories'] })
    },
  })

  const repos = reposQuery.data ?? []
  const registries = registriesQuery.data ?? []

  return (
    <div className="p-8 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Docker Repositories</h1>
        <p className="text-sm text-gray-500 mt-1">Manage Docker registry repositories and tags</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          value={registry}
          onChange={(e) => setRegistry(e.target.value)}
        >
          <option value="">All Registries</option>
          {registries.map((r) => (
            <option key={r.host} value={r.host}>{r.host}</option>
          ))}
        </select>

        <span className="text-sm text-gray-500 ml-auto">
          {reposQuery.isLoading ? 'Loading...' : `${repos.length} repositor${repos.length !== 1 ? 'ies' : 'y'}`}
        </span>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        {reposQuery.isError ? (
          <div className="p-8 text-center text-red-500 text-sm">
            Failed to load repositories. Is the API server running?
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Registry</th>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Internal</th>
                <th className="px-4 py-3">Last Synced</th>
                <th className="px-4 py-3">Sync Enabled</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {reposQuery.isLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-400">
                    Loading repositories...
                  </td>
                </tr>
              ) : repos.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-400">
                    No repositories found.
                  </td>
                </tr>
              ) : (
                repos.map((repo) => (
                  <tr key={repo.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-mono text-xs text-gray-600">{repo.registry}</td>
                    <td className="px-4 py-3">
                      <Link
                        to={`/docker/repositories/${repo.id}`}
                        className="text-blue-600 hover:text-blue-800 font-medium flex items-center gap-1"
                      >
                        {repo.name}
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      {repo.is_internal ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                          Yes
                        </span>
                      ) : (
                        <span className="text-gray-400">No</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-600 text-xs">
                      {repo.last_synced_at ? new Date(repo.last_synced_at).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-4 py-3">
                      {repo.sync_enabled ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          Enabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                          Disabled
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => syncMutation.mutate(repo.id)}
                        disabled={syncMutation.isPending}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                        Sync
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
