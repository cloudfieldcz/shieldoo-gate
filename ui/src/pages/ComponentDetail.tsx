import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Pencil } from 'lucide-react'
import { vulnApi, aiApi, type ScanFinding, type Ignore, type Component } from '../api/vulnerabilities'
import SeverityChip, { severityRank } from '../components/vuln/SeverityChip'
import SeverityCounts from '../components/vuln/SeverityCounts'
import TriggerBadge from '../components/vuln/TriggerBadge'
import ScannerPill from '../components/vuln/ScannerPill'
import IgnoreModal from '../components/vuln/IgnoreModal'
import IntegrationGuide from '../components/vuln/IntegrationGuide'
import ComponentEditModal from '../components/vuln/ComponentEditModal'

type Tab = 'active' | 'ignored' | 'history' | 'integration'

export default function ComponentDetail() {
  const { id } = useParams<{ id: string }>()
  const componentID = Number(id)
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<Tab>('active')
  const [modalFinding, setModalFinding] = useState<ScanFinding | null>(null)
  const [restoreFromIgnore, setRestoreFromIgnore] = useState<Ignore | null>(null)
  const [editOpen, setEditOpen] = useState(false)

  const { data: comp } = useQuery({
    queryKey: ['vuln', 'component', componentID],
    queryFn: () => vulnApi.get(componentID),
    enabled: Number.isFinite(componentID),
  })
  const { data: scans = [] } = useQuery({
    queryKey: ['vuln', 'component', componentID, 'scans'],
    queryFn: () => vulnApi.scans(componentID),
    enabled: Number.isFinite(componentID),
  })
  const lastScanID = scans[0]?.id
  const { data: findings = [] } = useQuery({
    queryKey: ['vuln', 'component', componentID, 'findings', lastScanID],
    queryFn: () => lastScanID ? vulnApi.findings(lastScanID) : Promise.resolve([]),
    enabled: !!lastScanID,
  })
  const { data: ignoreBundle = { active: [], expired: [] } } = useQuery({
    queryKey: ['vuln', 'component', componentID, 'ignores'],
    queryFn: () => vulnApi.listIgnoresWithExpired(componentID),
    enabled: Number.isFinite(componentID),
  })
  const ignores = ignoreBundle.active
  const expiredIgnores = ignoreBundle.expired
  const { data: fixPath } = useQuery({
    queryKey: ['vuln', 'component', componentID, 'fixpath'],
    queryFn: () => aiApi.fixPath(componentID),
    enabled: Number.isFinite(componentID),
  })

  const rescanMutation = useMutation({
    mutationFn: () => vulnApi.rescan(componentID),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['vuln', 'component', componentID] }),
  })
  const revokeMutation = useMutation({
    mutationFn: (ig: Ignore) => vulnApi.revokeIgnore(componentID, ig.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['vuln', 'component', componentID, 'ignores'] }),
  })

  if (!comp) return <div className="px-8 py-6">Loading…</div>

  const active = findings.filter((f) => !f.is_suppressed)
  const ignored = findings.filter((f) => f.is_suppressed)

  return (
    <div className="px-8 py-6 space-y-5">
      {/* Sticky header */}
      <div className="bg-white rounded-lg border border-gray-200 p-5">
        <div className="text-xs text-gray-500 mb-1">
          <Link to="/vulnerabilities" className="hover:underline">Vulnerabilities</Link>
          {' / '}
          <Link to={`/projects/${comp.project_id}`} className="hover:underline">{comp.project_id}</Link>
          {' / '}
          <span className="text-gray-700">{comp.name}</span>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-[24px] font-semibold text-slate-900">{comp.display_name || comp.name}</h1>
            <span className="inline-block mt-1 text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-700 font-mono">{comp.ecosystem}</span>
          </div>
          <div className="flex items-center gap-2">
            {scans[0] && (
              <>
                <span className="text-xs text-gray-500">Last scan: {new Date(scans[0].started_at).toLocaleString()}</span>
                <TriggerBadge trigger={scans[0].trigger} />
                <ScannerPill scanner="osv" status="ok" />
                <ScannerPill scanner="trivy" status="ok" />
              </>
            )}
            <button
              onClick={() => setEditOpen(true)}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-sm border border-gray-300 text-gray-700 rounded hover:bg-gray-50"
              title="Edit component metadata"
            >
              <Pencil className="w-3.5 h-3.5" /> Edit
            </button>
            <button
              onClick={() => rescanMutation.mutate()}
              disabled={rescanMutation.isPending}
              className="px-3 py-1.5 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
            >
              {rescanMutation.isPending ? 'Rescanning…' : 'Rescan now'}
            </button>
          </div>
        </div>
        {(comp.description || comp.repo_url) && (
          <div className="mt-3 text-xs text-gray-600 space-y-0.5">
            {comp.description && <div>{comp.description}</div>}
            {comp.repo_url && (
              <div>
                <span className="text-gray-400">repo: </span>
                <a href={comp.repo_url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline break-all">
                  {comp.repo_url}
                </a>
              </div>
            )}
          </div>
        )}
      </div>

      {fixPath && (
        <div className="rounded-lg border border-purple-200 bg-gradient-to-br from-indigo-50 to-violet-50 p-4">
          <div className="text-xs font-semibold text-purple-700 uppercase tracking-wider mb-1">AI INSIGHT</div>
          <div className="text-sm text-slate-900">{fixPath.summary}</div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <div className="flex gap-1">
          {(['active', 'ignored', 'history', 'integration'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm border-b-2 ${tab === t ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-600 hover:text-gray-900'}`}
            >
              {t === 'active' ? `Active CVEs (${active.length})` :
               t === 'ignored' ? `Ignored CVEs (${ignored.length})` :
               t === 'history' ? `Scan history (${scans.length})` : 'Integration'}
            </button>
          ))}
        </div>
      </div>

      {tab === 'active' && (
        <FindingTable findings={active} onIgnore={(f) => setModalFinding(f)} />
      )}
      {tab === 'ignored' && (
        <div className="space-y-4">
          <IgnoredTable ignores={ignores} onRestore={(ig) => revokeMutation.mutate(ig)} />
          {expiredIgnores.length > 0 && (
            <ExpiredIgnoresPanel ignores={expiredIgnores} onRestore={(ig) => setRestoreFromIgnore(ig)} />
          )}
        </div>
      )}
      {tab === 'history' && (
        <ScanHistoryTable scans={scans} />
      )}
      {tab === 'integration' && (
        <IntegrationGuide projectLabel={String(comp.project_id)} componentName={comp.name} />
      )}

      {modalFinding && lastScanID && (
        <IgnoreModal
          componentID={componentID}
          componentRepoURL={comp.repo_url}
          finding={modalFinding}
          scanRunID={lastScanID}
          aiEnabled={comp.ai_enabled}
          onClose={() => setModalFinding(null)}
          onCreated={() => {
            setModalFinding(null)
            queryClient.invalidateQueries({ queryKey: ['vuln', 'component', componentID] })
          }}
        />
      )}

      {restoreFromIgnore && lastScanID && (
        <IgnoreModal
          componentID={componentID}
          componentRepoURL={comp.repo_url}
          finding={{
            id: 0,
            scan_run_id: lastScanID,
            component_id: componentID,
            cve_id: restoreFromIgnore.cve_id,
            package_name: restoreFromIgnore.package_name,
            package_version: restoreFromIgnore.package_version ?? '',
            ecosystem: comp.ecosystem,
            severity: 'UNKNOWN',
            cvss_score: 0,
            detected_by: 'restore',
            is_suppressed: false,
          }}
          scanRunID={lastScanID}
          aiEnabled={comp.ai_enabled}
          initialReason={restoreFromIgnore.reason}
          restoreFromExpired
          onClose={() => setRestoreFromIgnore(null)}
          onCreated={() => {
            setRestoreFromIgnore(null)
            queryClient.invalidateQueries({ queryKey: ['vuln', 'component', componentID] })
          }}
        />
      )}

      {editOpen && (
        <ComponentEditModal
          component={comp as Component}
          onClose={() => setEditOpen(false)}
          onSaved={() => {
            setEditOpen(false)
            queryClient.invalidateQueries({ queryKey: ['vuln', 'component', componentID] })
          }}
        />
      )}
    </div>
  )
}

function FindingTable({ findings, onIgnore }: { findings: ScanFinding[]; onIgnore: (f: ScanFinding) => void }) {
  if (findings.length === 0) {
    return <div className="rounded-lg bg-green-50 border border-green-200 p-4 text-sm text-green-700">All clear at last scan.</div>
  }
  // Severity first (most important), then artifact name, then version + CVE for a stable order.
  const sorted = [...findings].sort((a, b) =>
    severityRank[a.severity] - severityRank[b.severity] ||
    a.package_name.localeCompare(b.package_name) ||
    a.package_version.localeCompare(b.package_version) ||
    a.cve_id.localeCompare(b.cve_id),
  )
  return (
    <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-gray-50 text-[11px] uppercase tracking-wider text-gray-500">
          <tr>
            <th className="text-left px-4 py-3">Severity</th>
            <th className="text-left px-4 py-3">CVE</th>
            <th className="text-left px-4 py-3">Package</th>
            <th className="text-left px-4 py-3">Fixed in</th>
            <th className="text-left px-4 py-3">Detected by</th>
            <th className="text-right px-4 py-3">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {sorted.map((f) => (
            <tr key={f.id} className="hover:bg-gray-50">
              <td className="px-4 py-3"><SeverityChip severity={f.severity} /></td>
              <td className="px-4 py-3">
                <a href={`https://osv.dev/vulnerability/${encodeURIComponent(f.cve_id)}`} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline font-mono text-xs">
                  {f.cve_id}
                </a>
              </td>
              <td className="px-4 py-3">
                <span className="font-mono text-xs">{f.package_name}@{f.package_version}</span>
              </td>
              <td className="px-4 py-3 text-green-700 font-mono text-xs">{f.fixed_version || '—'}</td>
              <td className="px-4 py-3 text-xs text-gray-600">{f.detected_by}</td>
              <td className="px-4 py-3 text-right">
                <button
                  onClick={() => onIgnore(f)}
                  className="text-xs px-2 py-1 rounded border border-gray-300 hover:bg-gray-50"
                >
                  Ignore
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function IgnoredTable({ ignores, onRestore }: { ignores: Ignore[]; onRestore: (i: Ignore) => void }) {
  if (ignores.length === 0) {
    return <div className="text-sm text-gray-400 italic">No ignored CVEs.</div>
  }
  return (
    <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-gray-50 text-[11px] uppercase tracking-wider text-gray-500">
          <tr>
            <th className="text-left px-4 py-3">CVE</th>
            <th className="text-left px-4 py-3">Package</th>
            <th className="text-left px-4 py-3">Reason</th>
            <th className="text-left px-4 py-3">Expires</th>
            <th className="text-left px-4 py-3">Ignored by</th>
            <th className="text-right px-4 py-3">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {ignores.map((ig) => (
            <tr key={ig.id} className="hover:bg-gray-50">
              <td className="px-4 py-3 font-mono text-xs">{ig.cve_id}</td>
              <td className="px-4 py-3 font-mono text-xs">{ig.package_name}</td>
              <td className="px-4 py-3 text-gray-700 text-xs truncate max-w-md" title={ig.reason}>{ig.reason}</td>
              <td className="px-4 py-3 text-xs text-gray-600">{ig.expires_at ? new Date(ig.expires_at).toLocaleDateString() : 'never'}</td>
              <td className="px-4 py-3 text-xs text-gray-600">{ig.created_by_email}</td>
              <td className="px-4 py-3 text-right">
                <button onClick={() => onRestore(ig)} className="text-xs px-2 py-1 rounded border border-gray-300 hover:bg-gray-50">
                  Restore
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ExpiredIgnoresPanel({ ignores, onRestore }: { ignores: Ignore[]; onRestore: (i: Ignore) => void }) {
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50/50 overflow-hidden">
      <div className="px-4 py-2 border-b border-amber-200 bg-amber-100/50">
        <div className="text-xs font-semibold text-amber-800 uppercase tracking-wider">
          Recently expired — restore?
        </div>
        <div className="text-xs text-amber-700 mt-0.5">
          These ignores reached <code className="font-mono">expires_at</code> and were auto-revoked.
          The CVE is now flagged again at the next scan. Restore to re-create the ignore with a fresh expiry.
        </div>
      </div>
      <table className="w-full text-sm">
        <thead className="bg-amber-100/30 text-[11px] uppercase tracking-wider text-amber-900">
          <tr>
            <th className="text-left px-4 py-2">CVE</th>
            <th className="text-left px-4 py-2">Package</th>
            <th className="text-left px-4 py-2">Reason</th>
            <th className="text-left px-4 py-2">Revoked</th>
            <th className="text-right px-4 py-2">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-amber-100">
          {ignores.map((ig) => (
            <tr key={ig.id} className="hover:bg-amber-50">
              <td className="px-4 py-3 font-mono text-xs">{ig.cve_id}</td>
              <td className="px-4 py-3 font-mono text-xs">{ig.package_name}</td>
              <td className="px-4 py-3 text-gray-700 text-xs truncate max-w-md" title={ig.reason}>{ig.reason}</td>
              <td className="px-4 py-3 text-xs text-amber-700">
                {ig.revoked_at ? new Date(ig.revoked_at).toLocaleDateString() : '—'}
              </td>
              <td className="px-4 py-3 text-right">
                <button
                  onClick={() => onRestore(ig)}
                  className="text-xs px-2 py-1 rounded bg-amber-600 text-white hover:bg-amber-700"
                >
                  Restore
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ScanHistoryTable({ scans }: { scans: any[] }) {
  if (scans.length === 0) return <div className="text-sm text-gray-400 italic">No scans yet.</div>
  return (
    <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-gray-50 text-[11px] uppercase tracking-wider text-gray-500">
          <tr>
            <th className="text-left px-4 py-3">Time</th>
            <th className="text-left px-4 py-3">Trigger</th>
            <th className="text-left px-4 py-3">Status</th>
            <th className="text-right px-4 py-3">CVEs</th>
            <th className="text-right px-4 py-3">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {scans.map((s) => (
            <tr key={s.id} className="hover:bg-gray-50">
              <td className="px-4 py-3 text-xs text-gray-600">{new Date(s.started_at).toLocaleString()}</td>
              <td className="px-4 py-3"><TriggerBadge trigger={s.trigger} /></td>
              <td className="px-4 py-3 text-xs">
                <span className={`font-mono ${s.status === 'failed' ? 'text-red-600' : 'text-gray-700'}`}>{s.status}</span>
              </td>
              <td className="px-4 py-3 text-right">
                <SeverityCounts critical={s.critical_count} high={s.high_count} medium={s.medium_count} />
              </td>
              <td className="px-4 py-3 text-right">
                <Link to={`/vulnerabilities/scan-runs/${s.id}`} className="text-xs text-blue-600 hover:underline">View findings</Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
