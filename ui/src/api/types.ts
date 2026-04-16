interface Artifact {
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
  has_override?: boolean
}

interface ArtifactStatus {
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
  metadata_json?: string
  user_email?: string
}

export interface TriageMetadata {
  decision: string
  confidence: number
  explanation: string
  model_used: string
  tokens_used: number
  cache_hit: boolean
}

export interface AuditMetadata {
  ai_triage?: TriageMetadata
}

export interface PolicyModeResponse {
  mode: 'strict' | 'balanced' | 'permissive'
}

export interface RescanQuarantinedResponse {
  queued: number
  message: string
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

interface ArtifactStatsSection {
  total: number
  clean: number
  suspicious: number
  quarantined: number
  pending_scan: number
}

interface RequestStatsSection {
  served_24h: number
  blocked_24h: number
  served_all: number
  blocked_all: number
}

export interface StatsSummary {
  artifacts: ArtifactStatsSection
  requests: RequestStatsSection
  by_period: Record<string, Record<string, number>>
}

interface ScannerHealth {
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

interface OverrideInfo {
  id: number
  scope: 'version' | 'package'
  reason: string
  created_by: string
  created_at: string
  expires_at?: string
}

export type ArtifactWithStatus = Artifact & { status: ArtifactStatus }
export type ArtifactDetail = Artifact & { status: ArtifactStatus; scan_results: ScanResult[]; active_overrides: OverrideInfo[] }

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

export interface UserInfo {
  sub: string
  email: string
  name: string
}

export interface APIKey {
  id: number
  name: string
  owner_email: string
  enabled: boolean
  created_at: string
  last_used_at?: string
}

export interface PublicURLs {
  pypi?: string
  npm?: string
  nuget?: string
  docker?: string
  maven?: string
  rubygems?: string
  gomod?: string
}

export interface APIKeyCreateResponse {
  id: number
  name: string
  owner_email: string
  enabled: boolean
  created_at: string
  token: string
}

// ---- v1.2+ projects & license policy ------------------------------------

export interface Project {
  id: number
  label: string
  display_name: string
  description?: string
  created_at: string
  created_via: 'lazy' | 'api' | 'seed'
  enabled: boolean
}

export interface ProjectsListResponse {
  projects: Project[]
}

export interface ProjectArtifact {
  id: string
  ecosystem: string
  name: string
  version: string
  first_used_at: string
  last_used_at: string
  use_count: number
}

export interface ProjectArtifactsResponse {
  artifacts: ProjectArtifact[] | null
}

export type LicensePolicyMode = 'inherit' | 'override' | 'disabled'
export type LicenseAction = 'allow' | 'warn' | 'block'
export type OrSemantics = 'any_allowed' | 'all_allowed'

export interface ProjectLicensePolicyView {
  project_id: number
  mode: LicensePolicyMode
  blocked?: string[]
  warned?: string[]
  allowed?: string[]
  unknown_action?: LicenseAction | ''
  updated_at?: string
  updated_by?: string
  effective_source?: string
  strict_required?: boolean
}

export interface ProjectLicensePolicyUpdate {
  mode: LicensePolicyMode
  blocked: string[]
  warned: string[]
  allowed: string[]
  unknown_action: LicenseAction | ''
}

export interface GlobalLicensePolicyView {
  enabled: boolean
  blocked: string[]
  warned: string[]
  allowed: string[]
  unknown_action: LicenseAction | ''
  on_sbom_error: LicenseAction | ''
  or_semantics: OrSemantics
  updated_at?: string
  updated_by?: string
  source: 'db' | 'config'
}

export interface GlobalLicensePolicyUpdate {
  enabled?: boolean
  blocked: string[]
  warned: string[]
  allowed: string[]
  unknown_action: LicenseAction
  on_sbom_error: LicenseAction
  or_semantics: OrSemantics
}

export interface ArtifactLicenses {
  artifact_id: string
  licenses: string[]
  component_count?: number
  generator?: string
  generated_at?: string
}
