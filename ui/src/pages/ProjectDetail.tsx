import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, FolderTree, Package, ScrollText, RotateCcw } from 'lucide-react'
import axios from 'axios'
import { projectsApi } from '../api/client'
import type { ProjectLicensePolicyUpdate } from '../api/types'
import LicensePolicyEditor, {
  type LicensePolicyValue,
} from '../components/LicensePolicyEditor'
import { formatDate } from '../utils/format'

type Tab = 'artifacts' | 'policy'

export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>()
  const projectId = Number(id)
  const [tab, setTab] = useState<Tab>('artifacts')

  const projectQ = useQuery({
    queryKey: ['project', projectId],
    queryFn: () => projectsApi.get(projectId),
    enabled: Number.isFinite(projectId),
  })

  if (!Number.isFinite(projectId)) {
    return <div className="p-8 text-sm text-red-700">Invalid project id.</div>
  }

  return (
    <div className="p-8 space-y-4">
      <Link
        to="/projects"
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-900"
      >
        <ArrowLeft className="w-4 h-4" /> Back to projects
      </Link>

      {projectQ.isLoading && <div className="text-sm text-gray-500">Loading…</div>}

      {projectQ.data && (
        <>
          <div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
              <FolderTree className="w-6 h-6 text-blue-600" />
              <span className="font-mono">{projectQ.data.label}</span>
              {projectQ.data.display_name && (
                <span className="text-lg text-gray-500 font-normal">
                  — {projectQ.data.display_name}
                </span>
              )}
            </h1>
            <p className="text-xs text-gray-500 mt-1">
              Created {formatDate(projectQ.data.created_at)} · via{' '}
              <span className="font-mono">{projectQ.data.created_via}</span> ·{' '}
              {projectQ.data.enabled ? 'enabled' : 'disabled'}
            </p>
            {projectQ.data.description && (
              <p className="text-sm text-gray-700 mt-2">{projectQ.data.description}</p>
            )}
          </div>

          <div className="border-b border-gray-200 flex gap-4">
            <TabButton active={tab === 'artifacts'} onClick={() => setTab('artifacts')}>
              <Package className="w-4 h-4" /> Artifacts
            </TabButton>
            <TabButton active={tab === 'policy'} onClick={() => setTab('policy')}>
              <ScrollText className="w-4 h-4" /> License policy
            </TabButton>
          </div>

          {tab === 'artifacts' && <ArtifactsTab projectId={projectId} />}
          {tab === 'policy' && <PolicyTab projectId={projectId} />}
        </>
      )}
    </div>
  )
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-2 px-3 py-2 text-sm border-b-2 -mb-px ${
        active
          ? 'border-blue-600 text-blue-700 font-medium'
          : 'border-transparent text-gray-600 hover:text-gray-900'
      }`}
    >
      {children}
    </button>
  )
}

function ArtifactsTab({ projectId }: { projectId: number }) {
  const q = useQuery({
    queryKey: ['project-artifacts', projectId],
    queryFn: () => projectsApi.listArtifacts(projectId),
  })

  if (q.isLoading) return <div className="text-sm text-gray-500">Loading artifacts…</div>
  if (q.isError) return <div className="text-sm text-red-700">Failed to load artifacts.</div>

  const artifacts = q.data ?? []
  if (artifacts.length === 0) {
    return (
      <div className="mt-4 p-6 rounded-md bg-gray-50 border border-gray-200 text-sm text-gray-600">
        This project has not pulled any artifacts yet. Usage is tracked after every proxy
        request, with a short debounce — run a package install against the proxy and
        refresh in ~30 s.
      </div>
    )
  }

  return (
    <div className="bg-white border border-gray-200 rounded-md overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
          <tr>
            <th className="px-4 py-2 text-left font-medium">Artifact</th>
            <th className="px-4 py-2 text-right font-medium">Uses</th>
            <th className="px-4 py-2 text-left font-medium">First used</th>
            <th className="px-4 py-2 text-left font-medium">Last used</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200">
          {artifacts.map((a) => (
            <tr key={a.id} className="hover:bg-gray-50">
              <td className="px-4 py-2">
                <Link
                  to={`/artifacts?name=${encodeURIComponent(a.name)}&version=${encodeURIComponent(a.version)}`}
                  className="font-mono text-xs text-blue-700 hover:underline"
                >
                  {a.id}
                </Link>
              </td>
              <td className="px-4 py-2 text-right tabular-nums">{a.use_count}</td>
              <td className="px-4 py-2 text-xs text-gray-500">{formatDate(a.first_used_at)}</td>
              <td className="px-4 py-2 text-xs text-gray-500">{formatDate(a.last_used_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function PolicyTab({ projectId }: { projectId: number }) {
  const qc = useQueryClient()

  const policyQ = useQuery({
    queryKey: ['project-license-policy', projectId],
    queryFn: () => projectsApi.getLicensePolicy(projectId),
  })

  const putMut = useMutation({
    mutationFn: (body: ProjectLicensePolicyUpdate) =>
      projectsApi.putLicensePolicy(projectId, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['project-license-policy', projectId] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: () => projectsApi.deleteLicensePolicy(projectId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['project-license-policy', projectId] })
    },
  })

  if (policyQ.isLoading) return <div className="text-sm text-gray-500">Loading…</div>
  if (policyQ.isError || !policyQ.data)
    return <div className="text-sm text-red-700">Failed to load policy.</div>

  const pv = policyQ.data

  const initial: LicensePolicyValue = {
    mode: pv.mode,
    blocked: pv.blocked ?? [],
    warned: pv.warned ?? [],
    allowed: pv.allowed ?? [],
    unknown_action: (pv.unknown_action as LicensePolicyValue['unknown_action']) ?? '',
  }

  return (
    <div className="space-y-4">
      <LicensePolicyEditor
        variant="project"
        value={initial}
        saving={putMut.isPending}
        modeOverrideDisabled={pv.strict_required}
        sourceLabel={pv.effective_source}
        hint={
          pv.strict_required ? (
            <>
              <strong>Strict mode required.</strong> The deployment is running with{' '}
              <span className="font-mono">projects.mode=lazy</span>, so per-project
              <em> override</em> is not honoured at runtime — the global policy still
              applies. Switch to strict mode (and pre-provision projects) if you want
              per-project overrides to take effect.
            </>
          ) : (
            <>
              Per-project policy. Leave mode as <strong>inherit</strong> to use the
              global policy unchanged, or <strong>override</strong> it with the lists
              below. <strong>disabled</strong> skips license checks entirely for this
              project.
            </>
          )
        }
        onSave={(next) => {
          putMut.mutate(
            {
              mode: (next.mode ?? 'inherit') as ProjectLicensePolicyUpdate['mode'],
              blocked: next.blocked,
              warned: next.warned,
              allowed: next.allowed,
              unknown_action: (next.unknown_action || '') as ProjectLicensePolicyUpdate['unknown_action'],
            },
            {
              onError: (err) => {
                if (axios.isAxiosError(err) && err.response?.status === 403) {
                  alert(err.response.data?.message || 'override requires strict mode')
                }
              },
            }
          )
        }}
      />

      {pv.updated_at && (
        <div className="flex items-center justify-between gap-2 text-xs text-gray-500 pt-2 border-t border-gray-200">
          <div>
            Last edited {formatDate(pv.updated_at)} by {pv.updated_by || '(unknown)'}
          </div>
          <button
            type="button"
            onClick={() => {
              if (
                window.confirm(
                  'Remove this per-project override? The project will revert to inheriting the global license policy. The cached effective policy is purged immediately.'
                )
              ) {
                deleteMut.mutate()
              }
            }}
            disabled={deleteMut.isPending}
            title="Delete project_license_policy row and fall back to global inheritance"
            className="inline-flex items-center gap-1 px-2 py-1 text-xs rounded bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            <RotateCcw className="w-3 h-3" />
            {deleteMut.isPending ? 'Removing…' : 'Remove override'}
          </button>
        </div>
      )}
    </div>
  )
}
