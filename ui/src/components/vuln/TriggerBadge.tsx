const colorByTrigger: Record<string, string> = {
  upload: 'bg-blue-100 text-blue-800',
  rescan: 'bg-purple-100 text-purple-800',
  manual: 'bg-gray-100 text-gray-700',
}

export default function TriggerBadge({ trigger }: { trigger?: string }) {
  if (!trigger) return null
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono ${colorByTrigger[trigger] ?? colorByTrigger.manual}`}>
      {trigger}
    </span>
  )
}
