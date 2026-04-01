import { useQuery } from '@tanstack/react-query'
import { statsApi, healthApi } from '../api/client'
import { AlertTriangle, Package, ShieldX, Archive, Activity, ShieldCheck, Clock, Ban } from 'lucide-react'
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
    <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-center gap-4 shadow-sm">
      <div className={`p-3 rounded-lg ${color}`}>
        <Icon className="w-6 h-6 text-white" />
      </div>
      <div>
        <p className="text-sm text-gray-500">{label}</p>
        <p className="text-2xl font-bold text-gray-900">{value}</p>
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

  const stats = statsQuery.data
  const health = healthQuery.data
  const isDegraded =
    health && Object.values(health.scanners).some((s) => !s.healthy)

  const chartData = stats?.by_period ? buildChartData(stats.by_period) : []

  return (
    <div className="p-8 space-y-6">
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
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
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
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
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
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-5 h-5 text-gray-500" />
          <h2 className="text-base font-semibold text-gray-900">Traffic Over Time</h2>
        </div>
        {statsQuery.isLoading ? (
          <div className="h-64 flex items-center justify-center text-gray-400 text-sm">
            Loading chart data...
          </div>
        ) : chartData.length === 0 ? (
          <div className="h-64 flex items-center justify-center text-gray-400 text-sm">
            No traffic data available.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={260}>
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

      {statsQuery.isError && (
        <p className="text-sm text-red-500">Failed to load stats. Is the API server running?</p>
      )}
    </div>
  )
}
