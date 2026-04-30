import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ScrollText, RotateCcw } from 'lucide-react'
import { globalLicensePolicyApi } from '../api/client'
import type { GlobalLicensePolicyUpdate } from '../api/types'
import LicensePolicyEditor, {
  type LicensePolicyValue,
} from '../components/LicensePolicyEditor'
import { formatDate } from '../utils/format'

export default function LicensePolicy() {
  const qc = useQueryClient()

  const policyQ = useQuery({
    queryKey: ['global-license-policy'],
    queryFn: () => globalLicensePolicyApi.get(),
  })

  const putMut = useMutation({
    mutationFn: (body: GlobalLicensePolicyUpdate) => globalLicensePolicyApi.put(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['global-license-policy'] })
    },
  })

  const resetMut = useMutation({
    mutationFn: () => globalLicensePolicyApi.reset(),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['global-license-policy'] })
    },
  })

  return (
    <div className="p-8 space-y-4 max-w-5xl">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <ScrollText className="w-6 h-6 text-blue-600" />
            License policy (global)
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Defines which SPDX licenses are blocked, warned, or allowed for every artifact
            served by this proxy. Per-project overrides are layered on top of this via
            the <em>Projects</em> page.
          </p>
        </div>
        {policyQ.data?.source === 'db' && (
          <button
            type="button"
            onClick={() => {
              if (
                window.confirm(
                  'Revert to the YAML fallback? This removes the runtime-edited row and restores the values from policy.licenses.* in docker/config.yaml. The per-project policy cache will be purged so inheritors pick up the reverted global immediately.'
                )
              ) {
                resetMut.mutate()
              }
            }}
            disabled={resetMut.isPending}
            title="Delete the runtime-edited global_license_policy row and revert to YAML config"
            className="inline-flex items-center gap-1.5 px-3 py-2 text-sm rounded-md bg-white border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            <RotateCcw className="w-4 h-4" />
            {resetMut.isPending ? 'Reverting…' : 'Revert to YAML'}
          </button>
        )}
      </div>

      {policyQ.isLoading && <div className="text-sm text-gray-500">Loading policy…</div>}
      {policyQ.isError && (
        <div className="p-3 rounded-md bg-red-50 border border-red-200 text-sm text-red-800">
          Failed to load global license policy.
        </div>
      )}

      {policyQ.data && (
        <>
          <div className="text-xs text-gray-600">
            Source:{' '}
            <span
              className={`font-mono px-1.5 py-0.5 rounded ${
                policyQ.data.source === 'db' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-700'
              }`}
            >
              {policyQ.data.source}
            </span>{' '}
            {policyQ.data.source === 'config'
              ? '— the policy below mirrors docker/config.yaml (policy.licenses.*). Saving will persist to the global_license_policy DB row, which then overrides the YAML config.'
              : '— runtime-edited values are in effect. Restart will re-apply these from the DB; they override policy.licenses.* in config.yaml.'}
            {policyQ.data.updated_at && (
              <>
                {' · Last edited '}
                {formatDate(policyQ.data.updated_at)}{' by '}
                {policyQ.data.updated_by || '(unknown)'}
              </>
            )}
          </div>

          <LicensePolicyEditor
            variant="global"
            value={toValue(policyQ.data)}
            saving={putMut.isPending}
            hint={
              <>
                Changes are applied <strong>live</strong>: the resolver, the per-project
                policy cache, and the <em>on_sbom_error</em> behaviour update immediately
                after save — no restart needed.
              </>
            }
            onSave={(next) => {
              putMut.mutate({
                enabled: next.enabled ?? true,
                blocked: next.blocked,
                warned: next.warned,
                allowed: next.allowed,
                unknown_action: (next.unknown_action || 'allow') as GlobalLicensePolicyUpdate['unknown_action'],
                on_sbom_error: (next.on_sbom_error || 'allow') as GlobalLicensePolicyUpdate['on_sbom_error'],
                or_semantics: next.or_semantics ?? 'any_allowed',
              })
            }}
          />
        </>
      )}
    </div>
  )
}

function toValue(p: {
  enabled: boolean
  blocked: string[]
  warned: string[]
  allowed: string[]
  unknown_action: string
  on_sbom_error: string
  or_semantics: 'any_allowed' | 'all_allowed'
}): LicensePolicyValue {
  return {
    enabled: p.enabled,
    blocked: p.blocked ?? [],
    warned: p.warned ?? [],
    allowed: p.allowed ?? [],
    unknown_action: (p.unknown_action as LicensePolicyValue['unknown_action']) ?? '',
    on_sbom_error: (p.on_sbom_error as LicensePolicyValue['on_sbom_error']) ?? '',
    or_semantics: p.or_semantics ?? 'any_allowed',
  }
}
