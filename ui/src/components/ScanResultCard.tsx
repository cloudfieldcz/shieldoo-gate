import type { ScanResult } from '../api/types'
import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react'

interface ScanResultCardProps {
  result: ScanResult
}

const verdictConfig = {
  CLEAN: { label: 'Clean', icon: CheckCircle, color: 'text-green-600', bg: 'bg-green-50 border-green-200' },
  SUSPICIOUS: { label: 'Suspicious', icon: AlertTriangle, color: 'text-yellow-600', bg: 'bg-yellow-50 border-yellow-200' },
  MALICIOUS: { label: 'Malicious', icon: XCircle, color: 'text-red-600', bg: 'bg-red-50 border-red-200' },
}

function parseFindings(json: string): string[] {
  try {
    const parsed = JSON.parse(json)
    if (Array.isArray(parsed)) return parsed.map((f) => String(f))
    if (typeof parsed === 'object' && parsed !== null) {
      return Object.entries(parsed).map(([k, v]) => `${k}: ${v}`)
    }
    return [String(parsed)]
  } catch {
    return json ? [json] : []
  }
}

export default function ScanResultCard({ result }: ScanResultCardProps) {
  const config = verdictConfig[result.verdict] ?? verdictConfig.CLEAN
  const Icon = config.icon
  const findings = parseFindings(result.findings_json)
  const confidencePct = Math.round(result.confidence * 100)

  return (
    <div className={`border rounded-lg p-4 ${config.bg}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Icon className={`w-5 h-5 ${config.color}`} />
          <div>
            <p className="text-sm font-semibold text-gray-900">{result.scanner_name}</p>
            <p className="text-xs text-gray-500">v{result.scanner_version} &bull; {new Date(result.scanned_at).toLocaleString()}</p>
          </div>
        </div>
        <span className={`text-xs font-semibold px-2 py-1 rounded ${config.color}`}>
          {config.label}
        </span>
      </div>

      {/* Confidence bar */}
      <div className="mt-3">
        <div className="flex justify-between text-xs text-gray-500 mb-1">
          <span>Confidence</span>
          <span>{confidencePct}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-1.5">
          <div
            className="h-1.5 rounded-full bg-blue-500"
            style={{ width: `${confidencePct}%` }}
          />
        </div>
      </div>

      {/* Duration */}
      <p className="mt-2 text-xs text-gray-500">Duration: {result.duration_ms} ms</p>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="mt-3">
          <p className="text-xs font-semibold text-gray-700 mb-1">Findings</p>
          <ul className="space-y-1">
            {findings.map((f, i) => (
              <li key={i} className="text-xs text-gray-700 bg-white bg-opacity-60 rounded px-2 py-1 font-mono break-all">
                {f}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
