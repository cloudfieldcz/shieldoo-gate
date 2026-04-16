import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, FolderTree, X, AlertTriangle } from 'lucide-react'
import axios from 'axios'
import { projectsApi } from '../api/client'
import type { Project } from '../api/types'
import { formatDate } from '../utils/format'

const LABEL_REGEX = /^[a-z0-9][a-z0-9_-]{0,63}$/

export default function Projects() {
  const qc = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)

  const listQ = useQuery({
    queryKey: ['projects'],
    queryFn: () => projectsApi.list(),
  })

  return (
    <div className="p-8 space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <FolderTree className="w-6 h-6 text-blue-600" />
            Projects
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Every proxy request is tagged with a project label (the Basic-auth username).
            In <strong>lazy</strong> mode labels auto-create a row; in <strong>strict</strong>{' '}
            mode only labels listed here can authenticate.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex items-center gap-2 px-3 py-2 text-sm rounded-md bg-blue-600 text-white hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          New project
        </button>
      </div>

      {listQ.isLoading && <div className="text-sm text-gray-500">Loading projects…</div>}

      {listQ.isError && (
        <div className="p-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          Failed to load projects.
        </div>
      )}

      {listQ.data && (
        <div className="bg-white border border-gray-200 rounded-md overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Label</th>
                <th className="px-4 py-2 text-left font-medium">Display name</th>
                <th className="px-4 py-2 text-left font-medium">Source</th>
                <th className="px-4 py-2 text-left font-medium">Created</th>
                <th className="px-4 py-2 text-left font-medium">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {listQ.data.map((p: Project) => (
                <tr key={p.id} className="hover:bg-gray-50">
                  <td className="px-4 py-2">
                    <Link
                      to={`/projects/${p.id}`}
                      className="font-mono text-blue-700 hover:underline"
                    >
                      {p.label}
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-gray-700">{p.display_name || '—'}</td>
                  <td className="px-4 py-2">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
                        p.created_via === 'seed'
                          ? 'bg-gray-100 text-gray-700'
                          : p.created_via === 'api'
                          ? 'bg-purple-100 text-purple-800'
                          : 'bg-amber-100 text-amber-800'
                      }`}
                    >
                      {p.created_via}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-500 text-xs">
                    {formatDate(p.created_at)}
                  </td>
                  <td className="px-4 py-2">
                    {p.enabled ? (
                      <span className="text-green-700 text-xs">enabled</span>
                    ) : (
                      <span className="text-gray-400 text-xs">disabled</span>
                    )}
                  </td>
                </tr>
              ))}
              {listQ.data.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-sm text-gray-500">
                    No projects yet. The <code>default</code> project is seeded on first boot —
                    or create one explicitly here.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {createOpen && (
        <CreateProjectModal
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            setCreateOpen(false)
            void qc.invalidateQueries({ queryKey: ['projects'] })
          }}
        />
      )}
    </div>
  )
}

function CreateProjectModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: () => void
}) {
  const [label, setLabel] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState<string | null>(null)

  const labelValid = label === '' || LABEL_REGEX.test(label)

  const createMutation = useMutation({
    mutationFn: () =>
      projectsApi.create({
        label,
        display_name: displayName || undefined,
        description: description || undefined,
      }),
    onSuccess: () => onCreated(),
    onError: (err: unknown) => {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.error || err.message)
      } else {
        setError('Create failed')
      }
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200">
          <h2 className="text-lg font-semibold">New project</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-gray-700"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-900 mb-1">
              Label <span className="text-red-600">*</span>
            </label>
            <input
              type="text"
              value={label}
              onChange={(e) => {
                setLabel(e.target.value.toLowerCase())
                setError(null)
              }}
              placeholder="e.g. backend-team"
              className={`w-full px-3 py-2 text-sm font-mono border rounded-md focus:outline-none focus:ring-2 ${
                labelValid
                  ? 'border-gray-300 focus:ring-blue-500'
                  : 'border-red-400 focus:ring-red-500'
              }`}
            />
            <p className="text-xs text-gray-500 mt-1">
              Lowercase, <span className="font-mono">[a-z0-9][a-z0-9_-]&#123;0,63&#125;</span>.
              This becomes the HTTP Basic-auth username on proxy requests.
            </p>
            {!labelValid && (
              <p className="text-xs text-red-600 mt-1 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" /> Label doesn't match the allowed pattern.
              </p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-900 mb-1">
              Display name
            </label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Backend Team"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-900 mb-1">
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              placeholder="Optional — short description visible in the admin UI"
              className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {error && (
            <div className="p-2 rounded bg-red-50 border border-red-200 text-sm text-red-800">
              {error}
            </div>
          )}
        </div>
        <div className="flex items-center justify-end gap-2 px-4 py-3 border-t border-gray-200 bg-gray-50">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-2 text-sm rounded-md bg-white border border-gray-300 text-gray-700 hover:bg-gray-100"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => {
              if (!labelValid || !label) return
              setError(null)
              createMutation.mutate()
            }}
            disabled={!label || !labelValid || createMutation.isPending}
            className="px-3 py-2 text-sm rounded-md bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
          >
            {createMutation.isPending ? 'Creating…' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  )
}
