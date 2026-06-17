import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Bug, Terminal } from 'lucide-react'
import { vulnApi, type ComponentRow } from '../api/vulnerabilities'
import { projectsApi } from '../api/client'
import { CountPill } from '../components/vuln/SeverityCounts'
import TriggerBadge from '../components/vuln/TriggerBadge'
import AIAnomalyBanner from '../components/vuln/AIAnomalyBanner'

const ecosystems = ['', 'pypi', 'npm', 'maven', 'go', 'rubygems', 'nuget', 'container', 'multi']
const severityFloors = ['', 'CRITICAL', 'HIGH', 'MEDIUM']

export default function Vulnerabilities() {
  const [project, setProject] = useState('')
  const [ecosystem, setEcosystem] = useState('')
  const [severityFloor, setSeverityFloor] = useState('')
  const [hasNew, setHasNew] = useState(false)
  const [q, setQ] = useState('')

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['vuln', 'list', project, ecosystem, severityFloor, hasNew, q],
    queryFn: () => vulnApi.list({
      project: project || undefined,
      ecosystem: ecosystem || undefined,
      severity_floor: severityFloor || undefined,
      has_new: hasNew || undefined,
      q: q || undefined,
    }),
  })

  const { data: summary } = useQuery({ queryKey: ['vuln', 'summary'], queryFn: () => vulnApi.summary() })
  const { data: projects } = useQuery({ queryKey: ['projects', 'list'], queryFn: () => projectsApi.list() })

  const items = data?.items ?? []
  const hasFilters = Boolean(project || ecosystem || severityFloor || hasNew || q)
  const isPristineEmpty = !isLoading && items.length === 0 && !hasFilters

  return (
    <div className="px-8 py-6 space-y-5">
      <div>
        <h1 className="text-[28px] font-bold tracking-tight text-slate-900">Vulnerabilities</h1>
        <p className="text-sm text-slate-500 mt-1">Cross-project triage of known CVEs in pinned dependencies.</p>
      </div>

      <AIAnomalyBanner />

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2.5">
        <input
          placeholder="Search component or CVE…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          className="px-3 py-1.5 rounded-md border border-gray-300 text-sm w-64"
        />
        <select
          value={project}
          onChange={(e) => setProject(e.target.value)}
          className="px-3 py-1.5 rounded-md border border-gray-300 text-sm w-40"
        >
          <option value="">All projects</option>
          {(projects ?? []).map((p) => (
            <option key={p.label} value={p.label}>{p.display_name || p.label}</option>
          ))}
        </select>
        <select value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} className="px-3 py-1.5 rounded-md border border-gray-300 text-sm">
          {ecosystems.map((e) => <option key={e} value={e}>{e || 'All ecosystems'}</option>)}
        </select>
        <select value={severityFloor} onChange={(e) => setSeverityFloor(e.target.value)} className="px-3 py-1.5 rounded-md border border-gray-300 text-sm">
          {severityFloors.map((s) => <option key={s} value={s}>{s || 'Any severity'}</option>)}
        </select>
        <label className="flex items-center gap-2 text-sm text-gray-700">
          <input type="checkbox" checked={hasNew} onChange={(e) => setHasNew(e.target.checked)} />
          New since last scan
        </label>
        <div className="flex-1" />
        <button onClick={() => refetch()} className="px-3 py-1.5 rounded-md border border-gray-300 text-sm hover:bg-gray-50">
          Refresh
        </button>
        <span className="text-xs text-gray-500">{items.length} components</span>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total CRITICAL" value={summary?.total_critical ?? 0} color="text-red-700" />
        <StatCard label="Total HIGH" value={summary?.total_high ?? 0} color="text-amber-600" />
        <StatCard label="Components with new CRITICAL" value={summary?.components_new_critical ?? 0} clickable onClick={() => setHasNew(true)} />
        <StatCard label="Stale components" value={summary?.stale_components ?? 0} clickable />
      </div>

      {/* Components table or pristine empty state */}
      {isPristineEmpty ? (
        <EmptyStateCTA />
      ) : (
        <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-[11px] uppercase tracking-wider text-gray-500">
              <tr>
                <th className="text-left px-4 py-3">Project</th>
                <th className="text-left px-4 py-3">Component</th>
                <th className="text-left px-4 py-3">Ecosystem</th>
                <th className="text-left px-4 py-3">Last scan</th>
                <th className="text-right px-4 py-3">Critical</th>
                <th className="text-right px-4 py-3">High</th>
                <th className="text-right px-4 py-3">Medium</th>
                <th className="text-right px-4 py-3">Δ since last</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {isLoading && (
                <tr><td colSpan={8} className="text-center py-8 text-gray-400">Loading…</td></tr>
              )}
              {!isLoading && items.length === 0 && hasFilters && (
                <tr><td colSpan={8} className="text-center py-12 text-gray-400">
                  <div className="font-medium text-gray-700 mb-2">No components match the active filters.</div>
                  <div className="text-sm">Try clearing the search box or relaxing severity / ecosystem.</div>
                </td></tr>
              )}
              {items.map((row) => <Row key={row.id} row={row} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function EmptyStateCTA() {
  return (
    <div className="rounded-xl border border-blue-100 bg-gradient-to-br from-blue-50 to-white p-8">
      <div className="flex items-start gap-4">
        <div className="rounded-lg bg-blue-100 p-3 flex-shrink-0">
          <Bug className="w-6 h-6 text-blue-700" />
        </div>
        <div className="flex-1">
          <h2 className="text-lg font-semibold text-slate-900">No components yet</h2>
          <p className="text-sm text-slate-600 mt-1">
            Vulnerability scanning is push-from-CI: your build pipeline uploads a CycloneDX SBOM,
            Shieldoo Gate scans it with OSV + Trivy, and the findings show up here.
          </p>

          <div className="mt-5 grid sm:grid-cols-3 gap-3 text-sm">
            <Step n={1} title="Generate a token">
              In <Link to="/profile?scope=scan:upload" className="text-blue-700 hover:underline">Profile → API keys</Link>
              {' '}create a key with the <code className="px-1 bg-white border rounded">scan:upload</code> scope.
            </Step>
            <Step n={2} title="Build a CycloneDX SBOM">
              Use Trivy or any CycloneDX generator: <code className="px-1 bg-white border rounded">trivy fs --format cyclonedx --output sbom.json .</code>
            </Step>
            <Step n={3} title="Push it to Shieldoo Gate">
              <code className="px-1 bg-white border rounded">curl -H "Authorization: Bearer $TOKEN" --data-binary @sbom.json …/components/$NAME/scans</code>
            </Step>
          </div>

          <div className="mt-5 rounded-lg bg-slate-900 text-slate-100 p-4 text-xs font-mono overflow-x-auto">
            <div className="text-slate-500 mb-1 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5" /> Copy-paste example
            </div>
            <pre className="whitespace-pre">{`export SGW_TOKEN="…"
PROJECT=myteam
COMPONENT=billing-api

trivy fs --format cyclonedx --output sbom.json .

curl -X POST \\
  -H "Authorization: Bearer $SGW_TOKEN" \\
  -H "Content-Type: application/vnd.cyclonedx+json" \\
  --data-binary @sbom.json \\
  https://shieldoo.example.com/api/v1/projects/$PROJECT/components/$COMPONENT/scans`}</pre>
          </div>
        </div>
      </div>
    </div>
  )
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-3">
      <div className="flex items-center gap-2 text-xs">
        <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-blue-600 text-white font-semibold">{n}</span>
        <span className="font-semibold text-slate-900">{title}</span>
      </div>
      <div className="mt-1.5 text-xs text-slate-600 leading-relaxed">{children}</div>
    </div>
  )
}

function StatCard({ label, value, color, clickable, onClick }: { label: string; value: number; color?: string; clickable?: boolean; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={!clickable}
      className={`text-left rounded-lg border border-gray-200 bg-white p-4 ${clickable ? 'hover:bg-gray-50 cursor-pointer' : 'cursor-default'}`}
    >
      <div className="text-xs uppercase tracking-wider text-gray-500">{label}</div>
      <div className={`text-[32px] font-mono font-semibold mt-1 ${color ?? 'text-slate-900'}`}>{value}</div>
    </button>
  )
}

function Row({ row }: { row: ComponentRow }) {
  return (
    <tr className="hover:bg-gray-50">
      <td className="px-4 py-3 text-gray-700">{row.project_label}</td>
      <td className="px-4 py-3">
        <Link to={`/vulnerabilities/components/${row.id}`} className="text-blue-600 hover:underline">
          {row.display_name || row.name}
        </Link>
      </td>
      <td className="px-4 py-3"><span className="text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-700 font-mono">{row.ecosystem}</span></td>
      <td className={`px-4 py-3 ${row.stale ? 'text-red-600' : 'text-gray-600'}`}>
        {row.last_scan_at ? new Date(row.last_scan_at).toLocaleString() : '—'}
        {row.last_scan_trigger && <span className="ml-2"><TriggerBadge trigger={row.last_scan_trigger} /></span>}
      </td>
      <td className="px-4 py-3 text-right"><CountPill tone="critical" count={row.critical_count} /></td>
      <td className="px-4 py-3 text-right"><CountPill tone="high" count={row.high_count} /></td>
      <td className="px-4 py-3 text-right"><CountPill tone="medium" count={row.medium_count} /></td>
      <td className="px-4 py-3 text-right tabular-nums">
        {row.new_critical_count > 0 ? (
          <span className="text-red-700 font-medium">+{row.new_critical_count} critical</span>
        ) : (
          <span className="text-gray-300">—</span>
        )}
      </td>
    </tr>
  )
}
