import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { vulnApi } from '../api/vulnerabilities'
import SeverityChip from '../components/vuln/SeverityChip'
import TriggerBadge from '../components/vuln/TriggerBadge'
import SBOMJSONViewer from '../components/vuln/SBOMJSONViewer'

type Tab = 'findings' | 'sbom'

export default function ScanRunDetail() {
  const { id } = useParams<{ id: string }>()
  const runID = Number(id)
  const [tab, setTab] = useState<Tab>('findings')
  const [sbom, setSBOM] = useState<unknown>(null)

  const { data: run } = useQuery({
    queryKey: ['vuln', 'scan-run', runID],
    queryFn: () => vulnApi.scanRun(runID),
    enabled: Number.isFinite(runID),
  })
  const { data: findings = [] } = useQuery({
    queryKey: ['vuln', 'scan-run', runID, 'findings'],
    queryFn: () => vulnApi.findings(runID),
    enabled: Number.isFinite(runID),
  })

  const loadSBOM = async () => {
    const r = await fetch(vulnApi.sbomURL(runID))
    if (r.ok) {
      try { setSBOM(await r.json()) } catch { setSBOM(await r.text()) }
    }
  }

  if (!run) return <div className="px-8 py-6">Loading…</div>

  return (
    <div className="px-8 py-6 space-y-5">
      <div className="bg-white rounded-lg border border-gray-200 p-5">
        <div className="text-xs text-gray-500 mb-1">
          <Link to="/vulnerabilities" className="hover:underline">Vulnerabilities</Link>
          {' / scan run #'}{run.id}
        </div>
        <div className="flex items-center justify-between">
          <h1 className="text-[24px] font-semibold text-slate-900">Scan run #{run.id}</h1>
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500">{new Date(run.started_at).toLocaleString()}</span>
            <TriggerBadge trigger={run.trigger} />
            <span className="text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-700 font-mono">{run.status}</span>
          </div>
        </div>
      </div>

      <div className="border-b border-gray-200">
        <div className="flex gap-1">
          {(['findings', 'sbom'] as const).map((t) => (
            <button
              key={t}
              onClick={() => { setTab(t); if (t === 'sbom' && sbom === null) loadSBOM() }}
              className={`px-4 py-2 text-sm border-b-2 ${tab === t ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-600 hover:text-gray-900'}`}
            >
              {t === 'findings' ? `Findings (${findings.length})` : 'SBOM'}
            </button>
          ))}
        </div>
      </div>

      {tab === 'findings' && (
        <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-[11px] uppercase tracking-wider text-gray-500">
              <tr>
                <th className="text-left px-4 py-3">Severity</th>
                <th className="text-left px-4 py-3">CVE</th>
                <th className="text-left px-4 py-3">Package</th>
                <th className="text-left px-4 py-3">Fixed in</th>
                <th className="text-left px-4 py-3">Detected by</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {findings.map((f) => (
                <tr key={f.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3"><SeverityChip severity={f.severity} /></td>
                  <td className="px-4 py-3"><a href={`https://osv.dev/vulnerability/${encodeURIComponent(f.cve_id)}`} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline font-mono text-xs">{f.cve_id}</a></td>
                  <td className="px-4 py-3 font-mono text-xs">{f.package_name}@{f.package_version}</td>
                  <td className="px-4 py-3 font-mono text-xs text-green-700">{f.fixed_version || '—'}</td>
                  <td className="px-4 py-3 text-xs text-gray-600">{f.detected_by}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'sbom' && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <a href={vulnApi.sbomURL(runID)} download className="px-3 py-1.5 text-sm rounded border border-gray-300 hover:bg-gray-50">
              Download SBOM
            </a>
          </div>
          {sbom ? <SBOMJSONViewer sbom={sbom} /> : <div className="text-sm text-gray-400">Loading SBOM…</div>}
        </div>
      )}
    </div>
  )
}
