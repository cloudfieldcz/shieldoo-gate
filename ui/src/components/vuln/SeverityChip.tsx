import type { Severity } from '../../api/vulnerabilities'

const colors: Record<Severity, string> = {
  CRITICAL: 'bg-[#7f1d1d] text-white',
  HIGH: 'bg-[#dc2626] text-white',
  MEDIUM: 'bg-[#f59e0b] text-white',
  LOW: 'bg-[#94a3b8] text-white',
  UNKNOWN: 'bg-gray-300 text-gray-800',
  INFO: 'bg-gray-300 text-gray-800',
}

export default function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wider ${colors[severity] ?? colors.UNKNOWN}`}>
      {severity}
    </span>
  )
}
