export interface Artifact {
  id: string
  ecosystem: string
  name: string
  version: string
  upstream_url: string
  sha256: string
  size_bytes: number
  cached_at: string
  last_accessed_at: string
  storage_path: string
}

export interface ArtifactStatus {
  artifact_id: string
  status: 'CLEAN' | 'SUSPICIOUS' | 'QUARANTINED' | 'PENDING_SCAN'
  quarantine_reason?: string
  quarantined_at?: string
  released_at?: string
}

export interface ScanResult {
  id: number
  artifact_id: string
  scanned_at: string
  scanner_name: string
  scanner_version: string
  verdict: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'
  confidence: number
  findings_json: string
  duration_ms: number
}

export interface AuditEntry {
  id: number
  ts: string
  event_type: string
  artifact_id?: string
  client_ip?: string
  user_agent?: string
  reason?: string
}

export interface PolicyOverride {
  id: number
  ecosystem: string
  name: string
  version: string
  scope: 'version' | 'package'
  reason: string
  created_by: string
  created_at: string
  expires_at?: string
  revoked: boolean
  revoked_at?: string
}

export interface StatsSummary {
  total_artifacts: number
  total_blocked: number
  total_quarantined: number
  total_served: number
  by_period: Record<string, Record<string, number>>
}

export interface ScannerHealth {
  healthy: boolean
  error?: string
}

export interface HealthStatus {
  status: string
  scanners: Record<string, ScannerHealth>
}

export interface PaginatedResponse<T> {
  data: T[]
  page: number
  per_page: number
  total: number
}

export type ArtifactWithStatus = Artifact & { status: ArtifactStatus }
export type ArtifactDetail = Artifact & { status: ArtifactStatus; scan_results: ScanResult[] }

export interface DockerRepository {
  id: number
  registry: string
  name: string
  is_internal: boolean
  created_at: string
  last_synced_at: string | null
  sync_enabled: boolean
}

export interface DockerTag {
  tag: string
  manifest_digest: string
  created_at: string
  updated_at: string
}

export interface DockerRegistry {
  host: string
  url: string
}
