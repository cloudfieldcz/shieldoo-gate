import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { healthApi, adminApi } from '../api/client'
import { CheckCircle, XCircle, RefreshCw, ShieldAlert, AlertTriangle } from 'lucide-react'

const POLICY_MODES = [
  {
    value: 'strict',
    label: 'Strict',
    description: 'Quarantines all suspicious artifacts regardless of severity. Most conservative.',
    color: 'border-red-200 bg-red-50',
    selectedColor: 'border-red-500 bg-red-50 ring-2 ring-red-500',
  },
  {
    value: 'balanced',
    label: 'Balanced',
    description: 'Uses severity + AI triage for MEDIUM findings; quarantines HIGH and above.',
    color: 'border-yellow-200 bg-yellow-50',
    selectedColor: 'border-yellow-500 bg-yellow-50 ring-2 ring-yellow-500',
  },
  {
    value: 'permissive',
    label: 'Permissive',
    description: 'Allows MEDIUM findings with a warning; quarantines only HIGH and above.',
    color: 'border-green-200 bg-green-50',
    selectedColor: 'border-green-500 bg-green-50 ring-2 ring-green-500',
  },
]

export default function Settings() {
  const qc = useQueryClient()
  const [rescanConfirm, setRescanConfirm] = useState(false)

  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: healthApi.check,
    retry: 1,
    refetchInterval: 30_000,
  })

  const policyModeQuery = useQuery({
    queryKey: ['policy-mode'],
    queryFn: adminApi.getPolicyMode,
    retry: 1,
  })

  const policyModeMutation = useMutation({
    mutationFn: (mode: string) => adminApi.setPolicyMode(mode),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['policy-mode'] })
    },
  })

  const rescanMutation = useMutation({
    mutationFn: () => adminApi.rescanQuarantined(),
    onSuccess: () => {
      setRescanConfirm(false)
      void qc.invalidateQueries({ queryKey: ['artifacts'] })
    },
  })

  const health = healthQuery.data
  const currentMode = policyModeQuery.data?.mode

  return (
    <div className="p-8 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-sm text-gray-500 mt-1">
          System configuration, policy mode, and scanner health.
        </p>
      </div>

      {/* Policy mode selector */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-gray-900">Policy Mode</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              Controls how suspicious artifacts are handled.
            </p>
          </div>
          {policyModeQuery.isLoading && (
            <span className="text-sm text-gray-400">Loading...</span>
          )}
          {policyModeQuery.isError && (
            <span className="text-sm text-amber-600">
              Could not load current mode (API may not support this yet)
            </span>
          )}
        </div>

        <div className="grid gap-3">
          {POLICY_MODES.map((mode) => {
            const isSelected = currentMode === mode.value
            return (
              <button
                key={mode.value}
                onClick={() => policyModeMutation.mutate(mode.value)}
                disabled={policyModeMutation.isPending || policyModeQuery.isLoading}
                className={`text-left px-4 py-3 rounded-lg border transition-all ${
                  isSelected ? mode.selectedColor : `${mode.color} hover:shadow-sm`
                } disabled:opacity-60`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-gray-900">{mode.label}</span>
                  {isSelected && (
                    <span className="text-xs font-medium text-gray-500 bg-white px-2 py-0.5 rounded">
                      Active
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-600 mt-1">{mode.description}</p>
              </button>
            )
          })}
        </div>

        {policyModeMutation.isError && (
          <p className="text-sm text-red-500">
            Failed to update policy mode. The API endpoint may not be available yet.
          </p>
        )}
        {policyModeMutation.isSuccess && (
          <p className="text-sm text-green-600">Policy mode updated successfully.</p>
        )}
      </div>

      {/* Rescan all quarantined */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-4">
        <div>
          <h2 className="text-base font-semibold text-gray-900">Bulk Rescan</h2>
          <p className="text-sm text-gray-500 mt-0.5">
            Queue all quarantined artifacts for a fresh rescan. Useful after policy mode changes
            or scanner updates.
          </p>
        </div>

        {!rescanConfirm ? (
          <button
            onClick={() => setRescanConfirm(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border border-orange-300 text-orange-700 bg-orange-50 hover:bg-orange-100 transition-colors"
          >
            <ShieldAlert className="w-4 h-4" />
            Rescan All Quarantined
          </button>
        ) : (
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 space-y-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-amber-900">
                  Are you sure?
                </p>
                <p className="text-xs text-amber-700 mt-1">
                  This will move all quarantined artifacts to PENDING_SCAN and trigger rescans.
                  Depending on the number of quarantined artifacts, this may take some time.
                </p>
              </div>
            </div>
            <div className="flex gap-2 ml-7">
              <button
                onClick={() => rescanMutation.mutate()}
                disabled={rescanMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-orange-600 text-white hover:bg-orange-700 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${rescanMutation.isPending ? 'animate-spin' : ''}`} />
                {rescanMutation.isPending ? 'Queuing...' : 'Confirm Rescan'}
              </button>
              <button
                onClick={() => setRescanConfirm(false)}
                disabled={rescanMutation.isPending}
                className="px-3 py-1.5 text-xs font-medium rounded-md border border-gray-300 text-gray-600 hover:bg-gray-50 disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {rescanMutation.isSuccess && (
          <p className="text-sm text-green-600">
            {rescanMutation.data?.queued ?? 0} artifact{(rescanMutation.data?.queued ?? 0) !== 1 ? 's' : ''} queued for rescan.
          </p>
        )}
        {rescanMutation.isError && (
          <p className="text-sm text-red-500">Failed to queue rescans. Please try again.</p>
        )}
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
            ['Version', `v${import.meta.env.VITE_APP_VERSION || 'dev'}`],
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
