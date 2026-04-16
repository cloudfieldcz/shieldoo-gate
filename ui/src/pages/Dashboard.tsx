import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { statsApi, healthApi, configApi } from '../api/client'
import { AlertTriangle, Package, ShieldX, Archive, Activity, ShieldCheck, Clock, Ban, BookOpen, ChevronDown, ChevronUp, Terminal, RefreshCw, ShieldAlert } from 'lucide-react'
import type { PublicURLs } from '../api/types'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from 'recharts'

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string
  value: number | string
  icon: React.ElementType
  color: string
}) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 px-3 py-2.5 flex items-center gap-3 shadow-sm">
      <div className={`p-2 rounded-lg ${color}`}>
        <Icon className="w-4 h-4 text-white" />
      </div>
      <div>
        <p className="text-xs text-gray-500">{label}</p>
        <p className="text-lg font-bold text-gray-900">{value}</p>
      </div>
    </div>
  )
}

function buildChartData(byPeriod: Record<string, Record<string, number>>) {
  return Object.entries(byPeriod)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([period, counts]) => ({
      period,
      served: counts['served'] ?? 0,
      blocked: counts['blocked'] ?? 0,
      quarantined: counts['quarantined'] ?? 0,
    }))
}

export default function Dashboard() {
  const statsQuery = useQuery({ queryKey: ['stats-summary'], queryFn: statsApi.summary, retry: 1 })
  const healthQuery = useQuery({ queryKey: ['health'], queryFn: healthApi.check, retry: 1 })
  const urlsQuery = useQuery({ queryKey: ['public-urls'], queryFn: configApi.publicURLs, retry: 1 })

  const stats = statsQuery.data
  const health = healthQuery.data
  const isDegraded =
    health && Object.values(health.scanners).some((s) => !s.healthy)

  const chartData = stats?.by_period ? buildChartData(stats.by_period) : []

  return (
    <div className="p-8 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">System overview and traffic metrics</p>
      </div>

      {/* Scanner health warning */}
      {isDegraded && (
        <div className="flex items-start gap-3 bg-yellow-50 border border-yellow-300 rounded-lg p-4">
          <AlertTriangle className="w-5 h-5 text-yellow-600 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-sm font-semibold text-yellow-800">Scanner Degraded</p>
            <p className="text-sm text-yellow-700 mt-0.5">
              One or more scanners are not healthy. New artifacts may not be fully scanned.
            </p>
            <ul className="mt-2 space-y-0.5">
              {health &&
                Object.entries(health.scanners).map(([name, status]) => (
                  <li key={name} className="text-xs text-yellow-700">
                    <span className="font-mono font-semibold">{name}</span>:{' '}
                    {status.healthy ? 'ok' : status.error ?? 'unhealthy'}
                  </li>
                ))}
            </ul>
          </div>
        </div>
      )}

      {/* Artifacts section */}
      <div>
        <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-3">Artifacts</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-3">
          <StatCard
            label="Total"
            value={statsQuery.isLoading ? '...' : (stats?.artifacts.total ?? 0)}
            icon={Package}
            color="bg-blue-500"
          />
          <StatCard
            label="Clean"
            value={statsQuery.isLoading ? '...' : (stats?.artifacts.clean ?? 0)}
            icon={ShieldCheck}
            color="bg-green-500"
          />
          <StatCard
            label="Suspicious"
            value={statsQuery.isLoading ? '...' : (stats?.artifacts.suspicious ?? 0)}
            icon={AlertTriangle}
            color="bg-orange-500"
          />
          <StatCard
            label="Quarantined"
            value={statsQuery.isLoading ? '...' : (stats?.artifacts.quarantined ?? 0)}
            icon={ShieldX}
            color="bg-red-500"
          />
          <StatCard
            label="Pending Scan"
            value={statsQuery.isLoading ? '...' : (stats?.artifacts.pending_scan ?? 0)}
            icon={Clock}
            color="bg-gray-400"
          />
        </div>
      </div>

      {/* Requests section */}
      <div>
        <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wider mb-3">Requests</h2>
        <div className="grid grid-cols-2 sm:grid-cols-2 xl:grid-cols-4 gap-3">
          <StatCard
            label="Served (24h)"
            value={statsQuery.isLoading ? '...' : (stats?.requests.served_24h ?? 0)}
            icon={Archive}
            color="bg-blue-500"
          />
          <StatCard
            label="Blocked (24h)"
            value={statsQuery.isLoading ? '...' : (stats?.requests.blocked_24h ?? 0)}
            icon={Ban}
            color="bg-red-500"
          />
          <StatCard
            label="Served (all time)"
            value={statsQuery.isLoading ? '...' : (stats?.requests.served_all ?? 0)}
            icon={Archive}
            color="bg-blue-300"
          />
          <StatCard
            label="Blocked (all time)"
            value={statsQuery.isLoading ? '...' : (stats?.requests.blocked_all ?? 0)}
            icon={Ban}
            color="bg-red-300"
          />
        </div>
      </div>

      {/* Traffic chart */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
        <div className="flex items-center gap-2 mb-3">
          <Activity className="w-4 h-4 text-gray-500" />
          <h2 className="text-sm font-semibold text-gray-900">Traffic Over Time</h2>
        </div>
        {statsQuery.isLoading ? (
          <div className="h-48 flex items-center justify-center text-gray-400 text-sm">
            Loading chart data...
          </div>
        ) : chartData.length === 0 ? (
          <div className="h-48 flex items-center justify-center text-gray-400 text-sm">
            No traffic data available.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="colorServed" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorQuarantined" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis dataKey="period" tick={{ fontSize: 11 }} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip />
              <Legend />
              <Area type="monotone" dataKey="served" stroke="#3b82f6" fill="url(#colorServed)" name="Served" />
              <Area type="monotone" dataKey="blocked" stroke="#ef4444" fill="url(#colorBlocked)" name="Blocked" />
              <Area type="monotone" dataKey="quarantined" stroke="#f59e0b" fill="url(#colorQuarantined)" name="Quarantined" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* How to section */}
      <HowToSection urls={urlsQuery.data} />

      {statsQuery.isError && (
        <p className="text-sm text-red-500">Failed to load stats. Is the API server running?</p>
      )}
    </div>
  )
}

function HowToSection({ urls }: { urls?: PublicURLs }) {
  const [open, setOpen] = useState(true)

  const pypi = urls?.pypi || 'http://<host>:5000'
  const npm = urls?.npm || '<host>:4873'
  const docker = urls?.docker || '<host>:5002'
  const nuget = urls?.nuget || 'http://<host>:5001'
  const gomod = urls?.gomod || 'http://<host>:8087'
  const rubygems = urls?.rubygems || 'http://<host>:8086'
  const maven = urls?.maven || 'http://<host>:8085'

  const npmHost = npm.replace(/^https?:\/\//, '')
  const dockerHost = docker.replace(/^https?:\/\//, '')
  const scheme = pypi.startsWith('https') ? 'https' : 'http'

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-6 text-left"
      >
        <div className="flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-indigo-500" />
          <h2 className="text-base font-semibold text-gray-900">Quick Start Guide</h2>
        </div>
        {open ? (
          <ChevronUp className="w-5 h-5 text-gray-400" />
        ) : (
          <ChevronDown className="w-5 h-5 text-gray-400" />
        )}
      </button>

      {open && (
        <div className="px-6 pb-6 space-y-5 border-t border-gray-100 pt-4">
          {/* How it works */}
          <div className="flex gap-3">
            <RefreshCw className="w-5 h-5 text-blue-500 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-gray-900">How it works</h3>
              <p className="text-sm text-gray-600 mt-1">
                Shieldoo Gate sits between your package manager and the upstream registry.
                The <strong>first download</strong> of any package is slower because the artifact is fetched,
                cached, and scanned for malware in real time. Subsequent requests are served instantly from cache.
              </p>
            </div>
          </div>

          {/* Connect ecosystems */}
          <div className="flex gap-3">
            <Terminal className="w-5 h-5 text-green-500 mt-0.5 flex-shrink-0" />
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-semibold text-gray-900">Connect your package managers</h3>
              <p className="text-sm text-gray-600 mt-1 mb-2">
                Generate an API key in <strong>Profile → API Keys</strong>, then configure your tools.
                All ecosystems use HTTP Basic Auth — <strong>project label</strong> as username, token as password.
                The project label segments audit events, usage tracking, and per-project license policy.
                Use any label (e.g. <code className="px-1 bg-gray-100 rounded text-xs">myteam</code>, <code className="px-1 bg-gray-100 rounded text-xs">backend-svc</code>) or <code className="px-1 bg-gray-100 rounded text-xs">default</code> if you don't need segmentation.
                In <strong>strict</strong> mode, an admin must create the project first in <strong>Projects</strong>.
              </p>
              <pre className="bg-gray-50 border border-gray-200 rounded-lg p-4 text-xs font-mono text-gray-800 overflow-x-auto whitespace-pre">
{`export SGW_TOKEN="your-token-here"
# Project label = your team/service name, or 'default'
PROJECT=myteam

# PyPI — pip
pip install --index-url ${scheme}://\${PROJECT}:\${SGW_TOKEN}@${pypi.replace(/^https?:\/\//, '')}/simple/ <package>

# PyPI — uv
UV_DEFAULT_INDEX=${scheme}://\${PROJECT}:\${SGW_TOKEN}@${pypi.replace(/^https?:\/\//, '')}/simple/ uv pip install <package>

# PyPI — pipenv
PIPENV_PYPI_MIRROR=${scheme}://\${PROJECT}:\${SGW_TOKEN}@${pypi.replace(/^https?:\/\//, '')}/simple/ pipenv install <package>

# npm (Node.js)
npm config set registry ${npm}/
npm config set //${npmHost}/:_auth $(printf "\${PROJECT}:\${SGW_TOKEN}" | base64)

# Docker
echo \${SGW_TOKEN} | docker login ${dockerHost} -u \${PROJECT} --password-stdin

# NuGet (.NET)
dotnet nuget add source ${nuget}/v3/index.json -n shieldoo -u \${PROJECT} -p \${SGW_TOKEN} --store-password-in-clear-text

# Go modules
GOPROXY=${gomod.replace(/^https?:\/\//, `${scheme}://\${PROJECT}:\${SGW_TOKEN}@`)} go get <module>

# Maven (Java) — add to ~/.m2/settings.xml
# <server><id>shieldoo</id><username>\${PROJECT}</username><password>\${SGW_TOKEN}</password></server>
# <mirror><id>shieldoo</id><url>${maven}/repository/</url><mirrorOf>central</mirrorOf></mirror>

# RubyGems
gem sources --add ${rubygems.replace(/^https?:\/\//, `${scheme}://\${PROJECT}:\${SGW_TOKEN}@`)}/`}
              </pre>
            </div>
          </div>

          {/* Troubleshooting */}
          <div className="flex gap-3">
            <ShieldAlert className="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-gray-900">Troubleshooting</h3>
              <ul className="text-sm text-gray-600 mt-1 space-y-2 list-disc list-inside">
                <li>
                  <strong>Install fails on first attempt?</strong> The scan may still be in progress. Simply
                  re-run the install command — once the scan finishes, the package will be served from cache.
                </li>
                <li>
                  <strong>Getting a 403 Forbidden?</strong> The artifact has been quarantined as potentially
                  malicious. Go to the <strong>Artifacts</strong> page, find the package, review the scan results,
                  and if you determine it is safe, click <strong>Release</strong> to allow downloads.
                </li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
