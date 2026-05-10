import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, FolderTree, Package, ScrollText, RotateCcw, ShieldCheck, ShieldX, Undo2, Bug } from 'lucide-react'
import { projectsApi } from '../api/client'
import { vulnApi } from '../api/vulnerabilities'
import type {
  ProjectArtifact,
  ProjectArtifactDecision,
  ProjectLicensePolicyUpdate,
  ProjectOverrideKind,
  ProjectOverrideRequest,
} from '../api/types'
import LicensePolicyEditor, {
  type LicensePolicyValue,
} from '../components/LicensePolicyEditor'
import OverrideModal from '../components/OverrideModal'
import ProjectLicenseOverridesPanel from '../components/ProjectLicenseOverridesPanel'
import { formatDate, truncateSha256 } from '../utils/format'

type Tab = 'artifacts' | 'policy' | 'vulns'

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
            <TabButton active={tab === 'vulns'} onClick={() => setTab('vulns')}>
              <Bug className="w-4 h-4" /> Vulnerabilities
            </TabButton>
          </div>

          {tab === 'artifacts' && <ArtifactsTab projectId={projectId} />}
          {tab === 'policy' && <PolicyTab projectId={projectId} />}
          {tab === 'vulns' && <VulnerabilitiesTab projectLabel={projectQ.data.label} />}
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

// modalState carries the row + intent for the override modal. The modal
// itself is unmounted (not just hidden) when state is null so its internal
// form clears between opens.
type ModalState = { artifact: ProjectArtifact; kind: ProjectOverrideKind } | null

function ArtifactsTab({ projectId }: { projectId: number }) {
  const qc = useQueryClient()
  const [modal, setModal] = useState<ModalState>(null)

  const q = useQuery({
    queryKey: ['project-artifacts', projectId],
    queryFn: () => projectsApi.listArtifacts(projectId),
  })

  const createOverride = useMutation({
    mutationFn: (req: ProjectOverrideRequest) => projectsApi.createOverride(projectId, req),
    onSuccess: () => {
      setModal(null)
      void qc.invalidateQueries({ queryKey: ['project-artifacts', projectId] })
      void qc.invalidateQueries({ queryKey: ['project-overrides', projectId] })
    },
  })

  const revokeOverride = useMutation({
    mutationFn: ({ overrideId, reason }: { overrideId: number; reason: string }) =>
      projectsApi.revokeOverride(projectId, overrideId, reason),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['project-artifacts', projectId] })
      void qc.invalidateQueries({ queryKey: ['project-overrides', projectId] })
    },
  })

  if (q.isLoading) return <div className="text-sm text-gray-500">Loading artifacts…</div>
  if (q.isError) return <div className="text-sm text-red-700">Failed to load artifacts.</div>

  const artifacts = q.data ?? []
  if (artifacts.length === 0) {
    // Even when no artifacts have been pulled, show the per-project overrides
    // panel so operators can see globals migrated by 036 or any standalone
    // allow/deny rows that exist server-side.
    return (
      <>
        <div className="mt-4 p-6 rounded-md bg-gray-50 border border-gray-200 text-sm text-gray-600">
          This project has not pulled any artifacts yet, has no license-blocked attempts,
          and no per-project overrides. Usage is tracked ~30 s after a proxy request.
        </div>
        <ProjectLicenseOverridesPanel projectId={projectId} />
      </>
    )
  }

  return (
    <>
      <div className="bg-white border border-gray-200 rounded-md overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
            <tr>
              <th className="px-4 py-2 text-left font-medium">Artifact</th>
              <th className="px-4 py-2 text-left font-medium">Decision</th>
              <th className="px-4 py-2 text-left font-medium">Licenses</th>
              <th className="px-4 py-2 text-right font-medium">Uses</th>
              <th className="px-4 py-2 text-left font-medium">Last activity</th>
              <th className="px-4 py-2 text-right font-medium">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {artifacts.map((a) => (
              <ArtifactRow
                key={`${a.ecosystem}:${a.name}:${a.version ?? ''}`}
                artifact={a}
                onWhitelist={() => setModal({ artifact: a, kind: 'allow' })}
                onBlacklist={() => setModal({ artifact: a, kind: 'deny' })}
                onRevert={() => {
                  if (!a.override_id) return
                  if (!window.confirm('Revoke this override?')) return
                  revokeOverride.mutate({
                    overrideId: a.override_id,
                    reason: 'reverted via project artifacts pane',
                  })
                }}
                disabled={createOverride.isPending || revokeOverride.isPending}
              />
            ))}
          </tbody>
        </table>
      </div>
      {modal && (
        <OverrideModal
          artifact={modal.artifact}
          kind={modal.kind}
          saving={createOverride.isPending}
          onCancel={() => setModal(null)}
          onSubmit={(req) => createOverride.mutate(req)}
        />
      )}
      {createOverride.isError && (
        <div className="mt-2 text-xs text-red-700">
          Failed to save override:{' '}
          {(createOverride.error as { response?: { data?: { error?: string } } })?.response?.data
            ?.error ?? 'unknown error'}
        </div>
      )}
      <ProjectLicenseOverridesPanel projectId={projectId} />
    </>
  )
}

function ArtifactRow({
  artifact,
  onWhitelist,
  onBlacklist,
  onRevert,
  disabled,
}: {
  artifact: ProjectArtifact
  onWhitelist: () => void
  onBlacklist: () => void
  onRevert: () => void
  disabled: boolean
}) {
  const lastActivity = artifact.last_blocked_at ?? artifact.last_used_at
  const fullId = artifact.id
    ?? `${artifact.ecosystem}:${artifact.name}${artifact.version ? `:${artifact.version}` : ''}`
  const displayId = artifact.id
    ? `${artifact.ecosystem}:${artifact.name}${artifact.version ? `:${truncateSha256(artifact.version)}` : ''}`
    : `${artifact.ecosystem}:${artifact.name}${artifact.version ? `:${truncateSha256(artifact.version)}` : ' (any version)'}`
  return (
    <tr className="hover:bg-gray-50">
      <td className="px-4 py-2">
        <div className="max-w-[24rem] truncate">
          {artifact.id ? (
            <Link
              to={`/artifacts?name=${encodeURIComponent(artifact.name)}&version=${encodeURIComponent(artifact.version ?? '')}`}
              title={fullId}
              className="font-mono text-xs text-blue-700 hover:underline truncate block max-w-full"
            >
              {displayId}
            </Link>
          ) : (
            <span
              className="font-mono text-xs text-gray-700 truncate block"
              title={fullId}
            >
              {displayId}
            </span>
          )}
        </div>
      </td>
      <td className="px-4 py-2">
        <DecisionPill decision={artifact.decision} reason={artifact.blocked_license} />
      </td>
      <td className="px-4 py-2">
        {artifact.licenses?.length ? (
          <div className="flex flex-wrap gap-1">
            {artifact.licenses.map((l: string) => (
              <span
                key={l}
                className="inline-block px-1.5 py-0.5 rounded text-xs font-mono bg-blue-50 text-blue-700 border border-blue-200"
              >
                {l}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-xs text-gray-300">—</span>
        )}
      </td>
      <td className="px-4 py-2 text-right tabular-nums">{artifact.use_count ?? '—'}</td>
      <td className="px-4 py-2 text-xs text-gray-500">{lastActivity ? formatDate(lastActivity) : '—'}</td>
      <td className="px-4 py-2 text-right">
        <DecisionAction
          decision={artifact.decision}
          disabled={disabled}
          onWhitelist={onWhitelist}
          onBlacklist={onBlacklist}
          onRevert={onRevert}
        />
      </td>
    </tr>
  )
}

function DecisionPill({
  decision,
  reason,
}: {
  decision: ProjectArtifactDecision
  reason?: string
}) {
  const styles: Record<ProjectArtifactDecision, { label: string; cls: string }> = {
    CLEAN: { label: 'Clean', cls: 'bg-gray-100 text-gray-700 border border-gray-200' },
    BLOCKED_LICENSE: {
      label: reason ? `Blocked: ${reason}` : 'Blocked (license)',
      cls: 'bg-red-50 text-red-700 border border-red-200',
    },
    WHITELISTED: { label: 'Whitelisted', cls: 'bg-green-50 text-green-700 border border-green-200' },
    BLACKLISTED: { label: 'Blacklisted', cls: 'bg-orange-50 text-orange-700 border border-orange-200' },
  }
  const s = styles[decision] ?? styles.CLEAN
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${s.cls}`}>
      {s.label}
    </span>
  )
}

function DecisionAction({
  decision,
  disabled,
  onWhitelist,
  onBlacklist,
  onRevert,
}: {
  decision: ProjectArtifactDecision
  disabled: boolean
  onWhitelist: () => void
  onBlacklist: () => void
  onRevert: () => void
}) {
  const baseBtn =
    'inline-flex items-center gap-1 px-2 py-1 text-xs rounded border focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-1 disabled:opacity-50'
  switch (decision) {
    case 'BLOCKED_LICENSE':
      return (
        <button
          type="button"
          onClick={onWhitelist}
          disabled={disabled}
          className={`${baseBtn} bg-white border-green-300 text-green-700 hover:bg-green-50 focus-visible:ring-green-500`}
        >
          <ShieldCheck className="w-3.5 h-3.5" /> Whitelist
        </button>
      )
    case 'CLEAN':
      return (
        <button
          type="button"
          onClick={onBlacklist}
          disabled={disabled}
          className={`${baseBtn} bg-white border-orange-300 text-orange-700 hover:bg-orange-50 focus-visible:ring-orange-500`}
        >
          <ShieldX className="w-3.5 h-3.5" /> Blacklist
        </button>
      )
    case 'WHITELISTED':
    case 'BLACKLISTED':
      return (
        <button
          type="button"
          onClick={onRevert}
          disabled={disabled}
          className={`${baseBtn} bg-white border-gray-300 text-gray-700 hover:bg-gray-50 focus-visible:ring-gray-400`}
        >
          <Undo2 className="w-3.5 h-3.5" /> Revert
        </button>
      )
    default:
      return null
  }
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
        sourceLabel={pv.effective_source}
        hint={
          <>
            Per-project policy. Leave mode as <strong>inherit</strong> to use the
            global policy unchanged, or <strong>override</strong> it with the lists
            below. <strong>disabled</strong> skips license checks entirely for this
            project.
          </>
        }
        onSave={(next) => {
          putMut.mutate({
            mode: (next.mode ?? 'inherit') as ProjectLicensePolicyUpdate['mode'],
            blocked: next.blocked,
            warned: next.warned,
            allowed: next.allowed,
            unknown_action: (next.unknown_action || '') as ProjectLicensePolicyUpdate['unknown_action'],
          })
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

function VulnerabilitiesTab({ projectLabel }: { projectLabel: string }) {
  const q = useQuery({
    queryKey: ['project-vulns', projectLabel],
    queryFn: () => vulnApi.list({ project: projectLabel, limit: 200 }),
  })

  if (q.isLoading) return <div className="text-sm text-gray-500">Loading components…</div>
  if (q.isError) return <div className="text-sm text-red-700">Failed to load components.</div>

  const items = q.data?.items ?? []
  if (items.length === 0) {
    return (
      <div className="mt-4 p-6 rounded-md bg-gray-50 border border-gray-200 text-sm text-gray-600 space-y-2">
        <p>No components have uploaded an SBOM for this project yet.</p>
        <p>
          See the{' '}
          <Link to="/vulnerabilities" className="text-blue-600 hover:underline">
            Vulnerabilities page
          </Link>{' '}
          for the integration guide. Each component pushes a CycloneDX SBOM via{' '}
          <code className="px-1 bg-white border rounded">POST /api/v1/projects/{projectLabel}/components/&lt;name&gt;/scans</code>.
        </p>
      </div>
    )
  }

  const totals = items.reduce(
    (acc, c) => ({
      critical: acc.critical + (c.critical_count ?? 0),
      high:     acc.high     + (c.high_count ?? 0),
      newCrit:  acc.newCrit  + (c.new_critical_count ?? 0),
    }),
    { critical: 0, high: 0, newCrit: 0 },
  )

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryStat label="Components" value={items.length} tone="neutral" />
        <SummaryStat label="Critical"   value={totals.critical} tone={totals.critical > 0 ? 'critical' : 'neutral'} />
        <SummaryStat label="High"       value={totals.high}     tone={totals.high > 0 ? 'high' : 'neutral'} />
        <SummaryStat label="New (CRIT/HIGH)" value={totals.newCrit} tone={totals.newCrit > 0 ? 'critical' : 'neutral'} />
      </div>

      <div className="bg-white border border-gray-200 rounded-md overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-gray-600 text-xs uppercase tracking-wide">
            <tr>
              <th className="px-4 py-2 text-left font-medium">Component</th>
              <th className="px-4 py-2 text-left font-medium">Ecosystem</th>
              <th className="px-4 py-2 text-right font-medium">Critical</th>
              <th className="px-4 py-2 text-right font-medium">High</th>
              <th className="px-4 py-2 text-right font-medium">New</th>
              <th className="px-4 py-2 text-left font-medium">Last scan</th>
              <th className="px-4 py-2 text-left font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {items.map((c) => (
              <tr key={c.id} className={c.stale ? 'bg-red-50/40' : ''}>
                <td className="px-4 py-2">
                  <Link to={`/vulnerabilities/components/${c.id}`} className="font-mono text-blue-700 hover:underline">
                    {c.display_name || c.name}
                  </Link>
                </td>
                <td className="px-4 py-2 text-xs uppercase tracking-wide text-gray-600">{c.ecosystem || '—'}</td>
                <td className={`px-4 py-2 text-right tabular-nums ${c.critical_count > 0 ? 'text-red-700 font-semibold' : 'text-gray-500'}`}>{c.critical_count}</td>
                <td className={`px-4 py-2 text-right tabular-nums ${c.high_count > 0 ? 'text-orange-700 font-semibold' : 'text-gray-500'}`}>{c.high_count}</td>
                <td className={`px-4 py-2 text-right tabular-nums ${(c.new_critical_count + c.new_high_count) > 0 ? 'text-red-700 font-semibold' : 'text-gray-500'}`}>
                  {c.new_critical_count + c.new_high_count}
                </td>
                <td className="px-4 py-2 text-gray-600">
                  {c.last_scan_at ? formatDate(c.last_scan_at) : '—'}
                  {c.last_scan_trigger && (
                    <span className="ml-1 text-xs text-gray-400">({c.last_scan_trigger})</span>
                  )}
                </td>
                <td className="px-4 py-2">
                  {c.stale ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-200">stale</span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-200">fresh</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function SummaryStat({ label, value, tone }: { label: string; value: number; tone: 'neutral' | 'critical' | 'high' }) {
  const cls =
    tone === 'critical' ? 'border-red-200 bg-red-50 text-red-900' :
    tone === 'high'     ? 'border-orange-200 bg-orange-50 text-orange-900' :
                          'border-gray-200 bg-white text-gray-900'
  return (
    <div className={`rounded-md border ${cls} p-3`}>
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
    </div>
  )
}
