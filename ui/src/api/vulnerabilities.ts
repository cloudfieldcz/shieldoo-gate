import axios from 'axios'

const api = axios.create({ baseURL: '/api/v1' })
api.interceptors.response.use((r) => r, (error) => {
  if (axios.isAxiosError(error) && error.response?.status === 401) {
    window.location.href = '/auth/login'
    return new Promise(() => {})
  }
  return Promise.reject(error)
})

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' | 'INFO'

export type ComponentRow = {
  id: number
  project_id: number
  project_label: string
  name: string
  display_name?: string
  ecosystem: string
  repo_url?: string
  ai_enabled: boolean
  enabled: boolean
  last_scan_at?: string
  last_scan_trigger?: string
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  new_critical_count: number
  new_high_count: number
  stale: boolean
}

export type Component = {
  id: number
  project_id: number
  name: string
  display_name?: string
  description?: string
  ecosystem: string
  repo_url?: string
  ai_enabled: boolean
  enabled: boolean
  last_scan_id?: number
}

export type ScanRun = {
  id: number
  component_id: number
  trigger: 'upload' | 'rescan' | 'manual'
  status: 'pending' | 'running' | 'done' | 'failed'
  sbom_blob_path: string
  sbom_size_bytes: number
  sbom_format: string
  sbom_sha256: string
  started_at: string
  finished_at?: string
  scanner_status?: string
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  new_critical_count: number
  new_high_count: number
  component_count: number
  error_message?: string
  integrity_violated: boolean
}

export type ScanFinding = {
  id: number
  scan_run_id: number
  component_id: number
  cve_id: string
  package_name: string
  package_version: string
  ecosystem: string
  severity: Severity
  cvss_score: number
  fixed_version?: string
  summary?: string
  detected_by: string
  is_suppressed: boolean
  suppressed_by?: number
}

export type Ignore = {
  id: number
  component_id: number
  cve_id: string
  package_name: string
  package_version?: string
  reason: string
  ai_draft_accepted: boolean
  expires_at?: string
  created_against_run_id?: number
  created_by_email: string
  created_at: string
  revoked_at?: string
  revoked_by_email?: string
}

export type VulnSummary = {
  total_critical: number
  total_high: number
  total_medium: number
  total_low: number
  components_new_critical: number
  stale_components: number
}

export const vulnApi = {
  list: (params: {
    project?: string; ecosystem?: string; severity_floor?: string; has_new?: boolean; q?: string;
    limit?: number; offset?: number;
  } = {}) => api.get<{ items: ComponentRow[] }>('/vulnerabilities/components', { params }).then((r) => r.data),

  get: (id: number) => api.get<Component>(`/vulnerabilities/components/${id}`).then((r) => r.data),

  update: (id: number, patch: Partial<Pick<Component, 'display_name' | 'description' | 'repo_url' | 'enabled' | 'ai_enabled'>>) =>
    api.patch(`/vulnerabilities/components/${id}`, patch).then((r) => r.data),

  byProject: (projectID: number) =>
    api.get<{ items: Component[] }>(`/projects/${projectID}/components`).then((r) => r.data.items),

  scans: (id: number, limit = 100) =>
    api.get<{ items: ScanRun[] }>(`/vulnerabilities/components/${id}/scans`, { params: { limit } }).then((r) => r.data.items),

  scanRun: (id: number) => api.get<ScanRun>(`/vulnerabilities/scan-runs/${id}`).then((r) => r.data),
  findings: (id: number) => api.get<{ items: ScanFinding[] }>(`/vulnerabilities/scan-runs/${id}/findings`).then((r) => r.data.items),
  sbomURL: (id: number) => `/api/v1/vulnerabilities/scan-runs/${id}/sbom`,

  rescan: (id: number) => api.post<{ scan_run_id: number }>(`/vulnerabilities/components/${id}/rescan`).then((r) => r.data),

  listIgnores: (componentID: number) =>
    api.get<{ items: Ignore[] }>(`/vulnerabilities/components/${componentID}/ignores`).then((r) => r.data.items),

  listIgnoresWithExpired: (componentID: number) =>
    api
      .get<{ items: Ignore[]; expired?: Ignore[] }>(
        `/vulnerabilities/components/${componentID}/ignores?include=expired`,
      )
      .then((r) => ({ active: r.data.items ?? [], expired: r.data.expired ?? [] })),

  createIgnore: (componentID: number, body: {
    cve_id: string; package_name: string; package_version?: string; reason: string;
    expires_at?: string | null; ai_draft_accepted?: boolean; against_run_id?: number;
  }) => api.post<Ignore>(`/vulnerabilities/components/${componentID}/ignores`, body).then((r) => r.data),

  revokeIgnore: (componentID: number, ignoreID: number) =>
    api.delete(`/vulnerabilities/components/${componentID}/ignores/${ignoreID}`).then((r) => r.data),

  summary: () => api.get<VulnSummary>('/vulnerabilities/summary').then((r) => r.data),
  badge: () => api.get<{ count: number }>('/vulnerabilities/badge').then((r) => r.data),
}

export type Anomaly = {
  id: number
  component_id: number
  detected_at: string
  triggering_run_id?: number | null
  severity_delta: number
  baseline_mean: number
  baseline_stddev: number
  sigma: number
  summary: string
}

export const aiApi = {
  anomalies: () =>
    api
      .get<{ items: Anomaly[] }>('/ai/anomalies')
      .then((r) => r.data.items ?? [])
      .catch(() => [] as Anomaly[]),
  acknowledgeAnomaly: (id: number) => api.post(`/ai/anomalies/${id}/acknowledge`).then((r) => r.data),
  fixPath: (componentID: number) =>
    api.get(`/ai/components/${componentID}/fix-path`).then((r) => r.data).catch(() => null),
  draft: (body: { component_id: number; cve_id: string; package_name: string; package_version: string }) =>
    api.post<{ reason: string }>('/ai/draft-ignore-reason', body).then((r) => r.data),
}
