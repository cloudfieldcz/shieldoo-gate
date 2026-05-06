import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Trash2, ArrowLeft, Plus } from 'lucide-react'
import { artifactsApi, dockerApi } from '../api/client'
import StatusBadge from '../components/StatusBadge'
import { renderSizeCell } from '../components/SizeCell'
import { formatDate } from '../utils/format'

// Mirror of internal/adapter/docker.MakeSafeName — keeps the UI-derived name in
// sync with the artifact-id slug used as `artifacts.name` in the database. We
// need this to look up cached manifests/tags for a given repository, since
// `artifacts.name` does not store the original `registry/path` form.
function makeSafeName(registry: string, imagePath: string): string {
  const prefix = registry === '' ? '_internal' : registry.replace(/[.:]/g, '_')
  const safePath = imagePath.replace(/\//g, '_')
  return `${prefix}_${safePath}`
}

export default function DockerRepositoryDetail() {
  const { id } = useParams<{ id: string }>()
  const repoId = Number(id)
  const qc = useQueryClient()
  const navigate = useNavigate()

  const [newTag, setNewTag] = useState('')
  const [newDigest, setNewDigest] = useState('')

  const reposQuery = useQuery({
    queryKey: ['docker-repositories'],
    queryFn: () => dockerApi.listRepositories(),
    retry: 1,
  })

  const tagsQuery = useQuery({
    queryKey: ['docker-tags', repoId],
    queryFn: () => dockerApi.listTags(repoId),
    enabled: !isNaN(repoId),
    retry: 1,
  })

  const syncMutation = useMutation({
    mutationFn: () => dockerApi.triggerSync(repoId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['docker-repositories'] })
      void qc.invalidateQueries({ queryKey: ['docker-tags', repoId] })
    },
  })

  const createTagMutation = useMutation({
    mutationFn: (data: { tag: string; manifest_digest: string }) =>
      dockerApi.createTag(repoId, data),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['docker-tags', repoId] })
      setNewTag('')
      setNewDigest('')
    },
  })

  const deleteTagMutation = useMutation({
    mutationFn: (tag: string) => dockerApi.deleteTag(repoId, tag),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['docker-tags', repoId] })
    },
  })

  const repo = reposQuery.data?.find((r) => r.id === repoId)
  const tags = tagsQuery.data ?? []

  // Cached artifacts (manifests) for this repo — filter the artifact list by
  // the same docker safe-name used as `artifacts.name`.
  const safeName = repo ? makeSafeName(repo.registry, repo.name) : ''
  const cachedQuery = useQuery({
    queryKey: ['docker-cached-artifacts', safeName],
    queryFn: () =>
      artifactsApi.list(1, 100, 'docker', undefined, safeName, undefined),
    enabled: !!safeName,
    retry: 1,
  })
  // The list endpoint matches `name` as a substring; tighten to an exact match
  // so we don't accidentally leak rows from sibling repos with overlapping
  // safe-name prefixes (e.g. `docker_io_library_post` vs `..._postgres`).
  const cached = (cachedQuery.data?.data ?? []).filter((a) => a.name === safeName)

  function handleCreateTag(e: React.FormEvent) {
    e.preventDefault()
    if (!newTag.trim() || !newDigest.trim()) return
    createTagMutation.mutate({ tag: newTag.trim(), manifest_digest: newDigest.trim() })
  }

  function handleDeleteTag(tag: string) {
    if (!window.confirm(`Delete tag "${tag}"? This cannot be undone.`)) return
    deleteTagMutation.mutate(tag)
  }

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          to="/docker"
          className="flex items-center gap-1 text-sm text-gray-500 hover:text-blue-600"
        >
          <ArrowLeft className="w-4 h-4" />
          Back
        </Link>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-gray-900">
            {repo ? `${repo.registry}/${repo.name}` : `Repository #${id}`}
          </h1>
          {repo && (
            <p className="text-sm text-gray-500 mt-1">
              {repo.is_internal ? 'Internal repository' : 'Mirror repository'}
              {' — '}
              Last synced: {repo.last_synced_at ? new Date(repo.last_synced_at).toLocaleString() : 'Never'}
            </p>
          )}
        </div>
        <button
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
          className="flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-md border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
          Sync Now
        </button>
      </div>

      {/* Cached manifests / artifacts pulled through this repository */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-gray-900">Cached Manifests</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Manifests and tags that clients have pulled through this proxy
            </p>
          </div>
          <span className="text-xs text-gray-500">
            {cachedQuery.isLoading
              ? 'Loading...'
              : `${cached.length} entr${cached.length !== 1 ? 'ies' : 'y'}`}
          </span>
        </div>

        {cachedQuery.isError ? (
          <div className="p-8 text-center text-red-500 text-sm">
            Failed to load cached manifests.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Reference</th>
                <th className="px-4 py-3">Status</th>
                <th
                  className="px-4 py-3"
                  title="Compressed download size for this image manifest. Multi-arch index entries show a badge — each platform-specific manifest pulled separately has its own size."
                >
                  Image size
                </th>
                <th className="px-4 py-3">Cached</th>
                <th className="px-4 py-3">Last Accessed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {cachedQuery.isLoading ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-400">
                    Loading cached manifests...
                  </td>
                </tr>
              ) : cached.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-400">
                    Nothing cached yet for this repository.
                  </td>
                </tr>
              ) : (
                cached.map((a) => {
                  const isDigest = a.version.startsWith('sha256:')
                  const shortRef = isDigest && a.version.length > 19
                    ? `${a.version.slice(0, 19)}…`
                    : a.version
                  return (
                    <tr
                      key={a.id}
                      onClick={() => navigate(`/artifacts?name=${encodeURIComponent(safeName)}&ecosystem=docker`)}
                      className="hover:bg-blue-50 cursor-pointer"
                    >
                      <td className="px-4 py-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-xs font-mono ${
                            isDigest
                              ? 'bg-gray-100 text-gray-700'
                              : 'bg-blue-50 text-blue-700 border border-blue-200'
                          }`}
                          title={a.version}
                        >
                          {shortRef}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={a.status.status} />
                      </td>
                      <td className="px-4 py-3 text-gray-600 text-xs">
                        {renderSizeCell(a)}
                      </td>
                      <td className="px-4 py-3 text-gray-600 text-xs">
                        {formatDate(a.cached_at)}
                      </td>
                      <td className="px-4 py-3 text-gray-600 text-xs">
                        {formatDate(a.last_accessed_at)}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Create tag form — only meaningful for internal (pushed) repos. Mirror
          repos receive their tag→digest mapping from the upstream sync, not
          from manual API calls. */}
      {repo?.is_internal && (
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
          <h2 className="text-sm font-semibold text-gray-900 mb-3">Create Tag</h2>
          <form onSubmit={handleCreateTag} className="flex flex-wrap gap-3 items-end">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Tag Name</label>
              <input
                type="text"
                value={newTag}
                onChange={(e) => setNewTag(e.target.value)}
                placeholder="e.g. latest"
                className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 w-48"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Manifest Digest</label>
              <input
                type="text"
                value={newDigest}
                onChange={(e) => setNewDigest(e.target.value)}
                placeholder="sha256:abc123..."
                className="border border-gray-300 rounded-md px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500 w-96"
              />
            </div>
            <button
              type="submit"
              disabled={createTagMutation.isPending || !newTag.trim() || !newDigest.trim()}
              className="flex items-center gap-1.5 px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
            >
              <Plus className="w-4 h-4" />
              {createTagMutation.isPending ? 'Creating...' : 'Create'}
            </button>
          </form>
          {createTagMutation.isError && (
            <p className="text-sm text-red-500 mt-2">Failed to create tag. Please try again.</p>
          )}
        </div>
      )}

      {/* Tags table — for internal repos this is the source of truth; for
          mirrors it's only populated by the sync job and is informational. */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900">
            {repo?.is_internal ? 'Tags' : 'Tag → Digest mappings'}
          </h2>
          <span className="text-xs text-gray-500">
            {tagsQuery.isLoading ? 'Loading...' : `${tags.length} tag${tags.length !== 1 ? 's' : ''}`}
          </span>
        </div>

        {tagsQuery.isError ? (
          <div className="p-8 text-center text-red-500 text-sm">
            Failed to load tags.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <th className="px-4 py-3">Tag</th>
                <th className="px-4 py-3">Digest</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3">Updated</th>
                {repo?.is_internal && <th className="px-4 py-3">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {tagsQuery.isLoading ? (
                <tr>
                  <td colSpan={repo?.is_internal ? 5 : 4} className="px-4 py-8 text-center text-gray-400">
                    Loading tags...
                  </td>
                </tr>
              ) : tags.length === 0 ? (
                <tr>
                  <td colSpan={repo?.is_internal ? 5 : 4} className="px-4 py-8 text-center text-gray-400">
                    No tags recorded yet.
                  </td>
                </tr>
              ) : (
                tags.map((tag) => (
                  <tr key={tag.tag} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-medium text-gray-900">{tag.tag}</td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-600 truncate max-w-xs" title={tag.manifest_digest}>
                      {tag.manifest_digest.length > 24
                        ? `${tag.manifest_digest.slice(0, 24)}...`
                        : tag.manifest_digest}
                    </td>
                    <td className="px-4 py-3 text-gray-600 text-xs">
                      {new Date(tag.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-gray-600 text-xs">
                      {new Date(tag.updated_at).toLocaleString()}
                    </td>
                    {repo?.is_internal && (
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleDeleteTag(tag.tag)}
                          disabled={deleteTagMutation.isPending}
                          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-red-300 text-red-700 hover:bg-red-50 disabled:opacity-50"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Delete
                        </button>
                      </td>
                    )}
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
