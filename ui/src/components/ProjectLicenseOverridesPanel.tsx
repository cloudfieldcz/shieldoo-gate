import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ScrollText, Undo2 } from 'lucide-react'
import { projectsApi } from '../api/client'
import type { ProjectOverride } from '../api/types'
import { formatDate } from '../utils/format'

type Props = { projectId: number }

/**
 * ProjectLicenseOverridesPanel lists per-project policy overrides
 * (allow/deny) and lets the operator revoke active ones.
 *
 * Surfaces what migration 036 backfilled (license-flavoured globals mirrored
 * into per-project rows) and any new overrides created via the artifacts pane
 * or the per-row Release button. Revoke flips `revoked=TRUE` server-side and
 * invalidates both this panel's query and the artifacts list so the project
 * artifact decision pill updates without a manual refresh.
 */
export default function ProjectLicenseOverridesPanel({ projectId }: Props) {
  const qc = useQueryClient()
  const overridesQ = useQuery<ProjectOverride[]>({
    queryKey: ['project-overrides', projectId],
    queryFn: () => projectsApi.listOverrides(projectId),
  })

  const revoke = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason: string }) =>
      projectsApi.revokeOverride(projectId, id, reason),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['project-overrides', projectId] })
      void qc.invalidateQueries({ queryKey: ['project-artifacts', projectId] })
    },
  })

  const all = overridesQ.data ?? []
  const active = all.filter((o) => !o.revoked)

  return (
    <section className="mt-6 rounded-lg border border-gray-200 bg-white">
      <header className="flex items-center gap-2 px-4 py-3 border-b border-gray-200">
        <ScrollText className="w-4 h-4 text-gray-500" />
        <h3 className="text-sm font-medium text-gray-800">Project license overrides</h3>
        <span className="ml-2 text-xs text-gray-500">
          {active.length} active{all.length > active.length ? ` · ${all.length - active.length} revoked` : ''}
        </span>
      </header>
      {overridesQ.isLoading ? (
        <p className="px-4 py-3 text-xs text-gray-500">Loading…</p>
      ) : overridesQ.isError ? (
        <p className="px-4 py-3 text-xs text-red-700">Failed to load overrides.</p>
      ) : active.length === 0 ? (
        <p className="px-4 py-3 text-xs text-gray-500">
          No active per-project overrides. Releases issued from a license-blocked
          artifact appear here.
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-gray-500">
            <tr>
              <th className="px-4 py-2 text-left font-medium">Package</th>
              <th className="px-4 py-2 text-left font-medium">Scope</th>
              <th className="px-4 py-2 text-left font-medium">Reason</th>
              <th className="px-4 py-2 text-left font-medium">Created</th>
              <th className="px-4 py-2 text-right font-medium">&nbsp;</th>
            </tr>
          </thead>
          <tbody>
            {active.map((o) => (
              <tr key={o.id} className="border-t border-gray-100">
                <td className="px-4 py-2 font-mono">
                  {o.ecosystem}/{o.name}
                  {o.version ? <span className="text-gray-500">@{o.version}</span> : null}
                </td>
                <td className="px-4 py-2 capitalize">
                  {o.scope} ({o.kind})
                </td>
                <td className="px-4 py-2 max-w-md truncate text-gray-600" title={o.reason}>
                  {o.reason}
                </td>
                <td className="px-4 py-2 text-gray-500">
                  {formatDate(o.created_at)}
                  {o.created_by && (
                    <span className="ml-1 text-gray-400">by {o.created_by}</span>
                  )}
                </td>
                <td className="px-4 py-2 text-right">
                  <button
                    type="button"
                    onClick={() => {
                      const reason = window.prompt('Reason for revoking this override?')
                      if (reason && reason.trim()) {
                        revoke.mutate({ id: o.id, reason: reason.trim() })
                      }
                    }}
                    disabled={revoke.isPending}
                    className="inline-flex items-center gap-1 px-2 py-1 text-xs text-red-700 hover:bg-red-50 rounded disabled:opacity-50"
                  >
                    <Undo2 className="w-3 h-3" /> Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
