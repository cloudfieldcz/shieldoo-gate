import { useQuery } from '@tanstack/react-query'
import { vulnApi } from '../../api/vulnerabilities'

export default function SidebarBadge() {
  const { data } = useQuery({
    queryKey: ['vuln', 'badge'],
    queryFn: () => vulnApi.badge(),
    refetchInterval: 30_000,
    retry: false,
  })
  if (!data || data.count === 0) return null
  return (
    <span className="ml-auto inline-flex items-center justify-center min-w-5 h-5 px-1.5 rounded-full bg-red-600 text-white text-[10px] font-semibold">
      {data.count}
    </span>
  )
}
