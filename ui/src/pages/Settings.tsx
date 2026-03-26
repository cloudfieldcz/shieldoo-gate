import { useQuery } from '@tanstack/react-query'
import { healthApi } from '../api/client'
import { CheckCircle, XCircle, RefreshCw } from 'lucide-react'

export default function Settings() {
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
    retry: 1,
    refetchInterval: 30_000,
  })

  const health = healthQuery.data

  return (
    <div className="p-8 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-sm text-gray-500 mt-1">
          System configuration and scanner health. Read-only in v1.0.
        </p>
      </div>

      {/* System health */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900">System Health</h2>
          <button
            onClick={() => void healthQuery.refetch()}
            className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-blue-600"
          >
            <RefreshCw className={`w-4 h-4 ${healthQuery.isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {healthQuery.isLoading ? (
          <p className="text-sm text-gray-400">Loading health status...</p>
        ) : healthQuery.isError ? (
          <p className="text-sm text-red-500">Failed to load health status.</p>
        ) : health ? (
          <>
            {/* Overall status */}
            <div className="flex items-center gap-3">
              {health.status === 'ok' || health.status === 'healthy' ? (
                <CheckCircle className="w-5 h-5 text-green-600" />
              ) : (
                <XCircle className="w-5 h-5 text-red-600" />
              )}
              <div>
                <p className="text-sm font-medium text-gray-900">Overall Status</p>
                <p className="text-sm text-gray-500 capitalize">{health.status}</p>
              </div>
            </div>

            {/* Scanner breakdown */}
            {Object.keys(health.scanners).length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-3">Scanners</h3>
                <div className="space-y-2">
                  {Object.entries(health.scanners).map(([name, status]) => {
                    const isOk = status.healthy
                    return (
                      <div
                        key={name}
                        className={`flex items-center justify-between px-4 py-3 rounded-lg border ${
                          isOk ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          {isOk ? (
                            <CheckCircle className="w-4 h-4 text-green-600" />
                          ) : (
                            <XCircle className="w-4 h-4 text-red-600" />
                          )}
                          <span className="text-sm font-medium text-gray-900 font-mono">
                            {name}
                          </span>
                        </div>
                        <span
                          className={`text-xs font-semibold ${
                            isOk ? 'text-green-700' : 'text-red-700'
                          }`}
                        >
                          {isOk ? 'ok' : status.error ?? 'unhealthy'}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </>
        ) : null}
      </div>

      {/* Info box */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-5 space-y-3">
        <h2 className="text-base font-semibold text-blue-900">Configuration</h2>
        <p className="text-sm text-blue-800">
          Configuration is managed via <code className="font-mono bg-blue-100 px-1 rounded">config.yaml</code> or
          environment variables. Editing configuration through the UI is not supported in v1.0.
        </p>
        <ul className="list-disc list-inside text-sm text-blue-800 space-y-1">
          <li>
            See <code className="font-mono bg-blue-100 px-1 rounded">config.example.yaml</code> for all options
          </li>
          <li>Restart the server after config changes</li>
          <li>Scanner settings are in the <code className="font-mono bg-blue-100 px-1 rounded">scanners:</code> section</li>
        </ul>
      </div>

      {/* About */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
        <h2 className="text-base font-semibold text-gray-900 mb-3">About</h2>
        <dl className="space-y-2">
          {[
            ['Product', 'Shieldoo Gate'],
            ['Version', 'v1.0.0'],
            ['License', 'Apache 2.0'],
            ['Repository', 'github.com/shieldoo/shieldoo-gate'],
          ].map(([label, value]) => (
            <div key={label} className="flex gap-4 text-sm">
              <dt className="w-24 text-gray-500 flex-shrink-0">{label}</dt>
              <dd className="text-gray-900 font-mono">{value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  )
}
