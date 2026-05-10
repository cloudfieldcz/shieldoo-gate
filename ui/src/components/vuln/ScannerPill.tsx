type Props = { scanner: string; status?: string }

export default function ScannerPill({ scanner, status = 'ok' }: Props) {
  const isOk = status === 'ok'
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono ${
      isOk ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
    }`}>
      {scanner}
    </span>
  )
}
