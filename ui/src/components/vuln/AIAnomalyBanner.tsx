import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Sparkles, X } from 'lucide-react'
import { aiApi, type Anomaly } from '../../api/vulnerabilities'

/**
 * AIAnomalyBanner — renders unacknowledged 3σ anomalies on Screen 1.
 *
 * Hidden when:
 *   - the AI feature is disabled (endpoint 404 → catch returns [])
 *   - no anomalies are pending (every viewer has acknowledged)
 *
 * Each anomaly is dismissible per-user (POST /ai/anomalies/{id}/acknowledge).
 * The banner stays out of `text-only / no dangerouslySetInnerHTML` territory:
 * `summary` is rendered as plain text.
 */
export default function AIAnomalyBanner() {
  const qc = useQueryClient()
  const { data: anomalies = [] } = useQuery({
    queryKey: ['ai', 'anomalies'],
    queryFn: aiApi.anomalies,
    refetchInterval: 60_000,
    retry: false,
  })

  const ackMut = useMutation({
    mutationFn: (id: number) => aiApi.acknowledgeAnomaly(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai', 'anomalies'] }),
  })

  if (anomalies.length === 0) return null

  return (
    <div className="space-y-2">
      {anomalies.slice(0, 3).map((a) => (
        <AnomalyRow key={a.id} anomaly={a} onDismiss={() => ackMut.mutate(a.id)} />
      ))}
      {anomalies.length > 3 && (
        <div className="text-xs text-slate-500 pl-3">
          +{anomalies.length - 3} more — open an individual component to triage and dismiss.
        </div>
      )}
    </div>
  )
}

function AnomalyRow({ anomaly, onDismiss }: { anomaly: Anomaly; onDismiss: () => void }) {
  return (
    <div className="rounded-lg border border-purple-200 bg-gradient-to-br from-indigo-50 to-violet-50 p-3 flex items-start gap-3">
      <div className="rounded-md bg-purple-600 text-white p-1.5 flex-shrink-0">
        <Sparkles className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-purple-700">
          AI Anomaly
          <span className="font-mono text-[10px] text-purple-600/80">σ={anomaly.sigma.toFixed(1)}</span>
        </div>
        <div className="text-sm text-slate-900 mt-0.5 break-words">{anomaly.summary}</div>
        <div className="mt-1 text-xs text-slate-500">
          <Link
            to={`/vulnerabilities/components/${anomaly.component_id}`}
            className="text-blue-700 hover:underline"
          >
            Open component →
          </Link>
          {anomaly.triggering_run_id ? (
            <>
              <span className="px-1 text-slate-300">·</span>
              <Link
                to={`/vulnerabilities/scan-runs/${anomaly.triggering_run_id}`}
                className="text-blue-700 hover:underline"
              >
                Triggering run #{anomaly.triggering_run_id}
              </Link>
            </>
          ) : null}
          <span className="px-1 text-slate-300">·</span>
          <span className="text-slate-500">
            baseline {anomaly.baseline_mean.toFixed(1)} ± {anomaly.baseline_stddev.toFixed(1)}
          </span>
        </div>
      </div>
      <button
        onClick={onDismiss}
        className="text-purple-500 hover:text-purple-700 p-1 -mt-1"
        title="Dismiss for me"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}
