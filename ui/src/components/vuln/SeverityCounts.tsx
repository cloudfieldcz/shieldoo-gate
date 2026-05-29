type Tone = 'critical' | 'high' | 'medium' | 'low'

const toneStyles: Record<Tone, { on: string; off: string }> = {
  critical: { on: 'bg-[#7f1d1d] text-white ring-[#7f1d1d]/20', off: 'bg-gray-50 text-gray-300 ring-gray-200' },
  high: { on: 'bg-[#dc2626] text-white ring-[#dc2626]/20', off: 'bg-gray-50 text-gray-300 ring-gray-200' },
  medium: { on: 'bg-[#f59e0b] text-white ring-[#f59e0b]/20', off: 'bg-gray-50 text-gray-300 ring-gray-200' },
  low: { on: 'bg-[#94a3b8] text-white ring-[#94a3b8]/20', off: 'bg-gray-50 text-gray-300 ring-gray-200' },
}

/** A single count badge — solid colored when count > 0, muted when zero so non-zero severities pop. */
export function CountPill({ tone, count, label }: { tone: Tone; count: number; label?: string }) {
  const s = toneStyles[tone]
  const active = count > 0
  return (
    <span
      className={`inline-flex items-center justify-center gap-0.5 min-w-[2rem] px-2 py-0.5 rounded-full text-xs font-semibold tabular-nums ring-1 ${active ? s.on : s.off}`}
      title={`${count} ${tone}`}
    >
      {count}
      {label ? <span className="text-[10px] font-bold opacity-80">{label}</span> : null}
    </span>
  )
}

/** Critical / High / Medium counts rendered as a compact row of colored pills. */
export default function SeverityCounts({
  critical,
  high,
  medium,
  labels = true,
}: {
  critical: number
  high: number
  medium: number
  labels?: boolean
}) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <CountPill tone="critical" count={critical} label={labels ? 'C' : undefined} />
      <CountPill tone="high" count={high} label={labels ? 'H' : undefined} />
      <CountPill tone="medium" count={medium} label={labels ? 'M' : undefined} />
    </span>
  )
}
