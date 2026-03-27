interface StatusBadgeProps {
  status: 'CLEAN' | 'SUSPICIOUS' | 'QUARANTINED' | 'PENDING_SCAN'
}

const statusConfig = {
  CLEAN: { label: 'Clean', className: 'bg-green-100 text-green-800' },
  SUSPICIOUS: { label: 'Suspicious', className: 'bg-yellow-100 text-yellow-800' },
  QUARANTINED: { label: 'Quarantined', className: 'bg-red-100 text-red-800' },
  PENDING_SCAN: { label: 'Pending Scan', className: 'bg-gray-100 text-gray-700' },
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const config = statusConfig[status] ?? { label: status, className: 'bg-gray-100 text-gray-700' }
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.className}`}
    >
      {config.label}
    </span>
  )
}
