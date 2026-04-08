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

type FindingValue = {
  severity?: string
  category?: string
  description?: string
  location?: string
  IoCs?: string[]
  iocs?: string[]
}

function formatFinding(finding: FindingValue): string {
  const parts = [finding.category, finding.severity, finding.description, finding.location ? `at ${finding.location}` : undefined]
    .filter(Boolean)

  const iocs = finding.IoCs ?? finding.iocs
  if (Array.isArray(iocs) && iocs.length > 0) {
    parts.push(`IoCs: ${iocs.join(', ')}`)
  }

  if (parts.length > 0) return parts.join(' | ')
  return JSON.stringify(finding)
}

function parseFindings(json: string): string[] {
  if (!json || json === 'null' || json === '[]') return []
  try {
    const parsed = JSON.parse(json)
    if (parsed === null || parsed === undefined) return []
    if (Array.isArray(parsed)) {
      if (parsed.length === 0) return []
      return parsed.map((f) => {
        if (typeof f === 'string') return f
        if (typeof f === 'object' && f !== null) return formatFinding(f as FindingValue)
        return String(f)
      })
    }
    if (typeof parsed === 'object' && parsed !== null) {
      return [formatFinding(parsed as FindingValue)]
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

  // Compact single-line layout for CLEAN results with no findings
  if (result.verdict === 'CLEAN' && findings.length === 0) {
    return (
      <div className={`border rounded-lg px-3 py-2 ${config.bg} flex items-center justify-between`}>
        <div className="flex items-center gap-2 min-w-0">
          <Icon className={`w-4 h-4 flex-shrink-0 ${config.color}`} />
          <span className="text-sm font-medium text-gray-900 truncate">{result.scanner_name}</span>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          <span className="text-[11px] text-gray-400">{result.duration_ms}ms</span>
          <span className={`text-xs font-semibold ${config.color}`}>{config.label}</span>
        </div>
      </div>
    )
  }

  // Full card for SUSPICIOUS/MALICIOUS or CLEAN with findings
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

      {/* Reputation risk score gauge (for builtin-reputation scanner) */}
      {result.scanner_name === 'builtin-reputation' && result.verdict !== 'CLEAN' ? (
        <div className="mt-3">
          <div className="flex justify-between text-xs text-gray-500 mb-1">
            <span>Risk Score</span>
            <span className={`font-semibold ${
              confidencePct >= 80 ? 'text-red-600' : confidencePct >= 50 ? 'text-yellow-600' : 'text-green-600'
            }`}>
              {confidencePct}%
            </span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2.5">
            <div
              className={`h-2.5 rounded-full transition-all ${
                confidencePct >= 80 ? 'bg-red-500' : confidencePct >= 50 ? 'bg-yellow-500' : 'bg-green-500'
              }`}
              style={{ width: `${confidencePct}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-gray-400 mt-0.5">
            <span>Low risk</span>
            <span>High risk</span>
          </div>
        </div>
      ) : (
        /* Confidence bar (standard scanners) */
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
      )}

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
