import axios from 'axios'
import type {
  ArtifactWithStatus,
  ArtifactDetail,
  AuditEntry,
  PolicyOverride,
  StatsSummary,
  HealthStatus,
  PublicURLs,
  PaginatedResponse,
  DockerRepository,
  DockerTag,
  DockerRegistry,
  UserInfo,
  APIKey,
  APIKeyCreateResponse,
  PolicyModeResponse,
  RescanQuarantinedResponse,
  Project,
  ProjectsListResponse,
  ProjectArtifactsResponse,
  ProjectLicensePolicyView,
  ProjectLicensePolicyUpdate,
  GlobalLicensePolicyView,
  GlobalLicensePolicyUpdate,
  ArtifactLicenses,
} from './types'

const api = axios.create({
  baseURL: '/api/v1',
})

// Axios instance for auth endpoints (no /api/v1 prefix).
const authApi = axios.create({})

// Redirect to OIDC login on 401 (unauthenticated).
const on401 = (error: unknown) => {
  if (axios.isAxiosError(error) && error.response?.status === 401) {
    window.location.href = '/auth/login'
    return new Promise(() => {}) // never resolves — page is navigating away
  }
  return Promise.reject(error)
}
api.interceptors.response.use((r) => r, on401)
authApi.interceptors.response.use((r) => r, on401)

export const artifactsApi = {
  list: (page = 1, perPage = 50, ecosystem?: string, status?: string, name?: string, version?: string) =>
    api
      .get<PaginatedResponse<ArtifactWithStatus>>('/artifacts', {
        params: { page, per_page: perPage, ecosystem, status, name, version },
      })
      .then((r) => r.data),

  get: (id: string) =>
    api.get<ArtifactDetail>(`/artifacts/${encodeURIComponent(id)}`).then((r) => r.data),

  rescan: (id: string) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/rescan`).then((r) => r.data),

  quarantine: (id: string) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/quarantine`).then((r) => r.data),

  release: (id: string) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/release`).then((r) => r.data),

  delete: (id: string) =>
    api.delete(`/artifacts/${encodeURIComponent(id)}`).then((r) => r.data),
}

export const statsApi = {
  summary: () => api.get<StatsSummary>('/stats/summary').then((r) => r.data),
}

export const auditApi = {
  list: (page = 1, perPage = 50, eventType?: string) =>
    api
      .get<PaginatedResponse<AuditEntry>>('/audit', {
        params: { page, per_page: perPage, event_type: eventType },
      })
      .then((r) => r.data),
}

export const overridesApi = {
  list: (page = 1, perPage = 50, active?: boolean, ecosystem?: string, name?: string) =>
    api
      .get<PaginatedResponse<PolicyOverride>>('/overrides', {
        params: { page, per_page: perPage, active: active ? 'true' : undefined, ecosystem, name },
      })
      .then((r) => r.data),

  create: (data: { ecosystem: string; name: string; version: string; scope: string; reason: string }) =>
    api.post('/overrides', data).then((r) => r.data),

  revoke: (id: number) =>
    api.delete(`/overrides/${id}`).then((r) => r.data),
}

export const healthApi = {
  check: () => api.get<HealthStatus>('/health').then((r) => r.data),
}

export const configApi = {
  publicURLs: () => api.get<PublicURLs>('/public-urls').then((r) => r.data),
}

export const dockerApi = {
  listRepositories: (registry?: string) =>
    api
      .get<DockerRepository[]>('/docker/repositories', {
        params: registry ? { registry } : {},
      })
      .then((r) => r.data),

  listTags: (repoId: number) =>
    api.get<DockerTag[]>(`/docker/repositories/${repoId}/tags`).then((r) => r.data),

  createTag: (repoId: number, data: { tag: string; manifest_digest: string }) =>
    api.post<DockerTag>(`/docker/repositories/${repoId}/tags`, data).then((r) => r.data),

  deleteTag: (repoId: number, tag: string) =>
    api.delete(`/docker/repositories/${repoId}/tags/${encodeURIComponent(tag)}`),

  triggerSync: (repoId: number) =>
    api.post(`/docker/sync/${repoId}`),

  listRegistries: () =>
    api.get<DockerRegistry[]>('/docker/registries').then((r) => r.data),
}

export const userApi = {
  me: () => authApi.get<UserInfo>('/auth/userinfo').then((r) => r.data),
  logout: () => authApi.post('/auth/logout'),
}

export const apiKeysApi = {
  list: () => api.get<APIKey[]>('/api-keys').then((r) => r.data),
  create: (name: string) =>
    api.post<APIKeyCreateResponse>('/api-keys', { name }).then((r) => r.data),
  revoke: (id: number) => api.delete(`/api-keys/${id}`),
}

export const adminApi = {
  rescanQuarantined: () =>
    api.post<RescanQuarantinedResponse>('/admin/rescan-quarantined').then((r) => r.data),

  getPolicyMode: () =>
    api.get<PolicyModeResponse>('/admin/policy-mode').then((r) => r.data),

  setPolicyMode: (mode: string) =>
    api.put<PolicyModeResponse>('/admin/policy-mode', { mode }).then((r) => r.data),
}

// ---- v1.2+ projects & licenses ------------------------------------------

export const projectsApi = {
  list: () =>
    api.get<ProjectsListResponse>('/projects').then((r) => r.data.projects),

  get: (id: number) =>
    api.get<Project>(`/projects/${id}`).then((r) => r.data),

  create: (data: { label: string; display_name?: string; description?: string }) =>
    api.post<Project>('/projects', data).then((r) => r.data),

  update: (id: number, data: { display_name?: string; description?: string; enabled?: boolean }) =>
    api.patch<Project>(`/projects/${id}`, data).then((r) => r.data),

  disable: (id: number) => api.delete(`/projects/${id}`),

  listArtifacts: (id: number) =>
    api.get<ProjectArtifactsResponse>(`/projects/${id}/artifacts`).then((r) => r.data.artifacts ?? []),

  getLicensePolicy: (id: number) =>
    api.get<ProjectLicensePolicyView>(`/projects/${id}/license-policy`).then((r) => r.data),

  putLicensePolicy: (id: number, body: ProjectLicensePolicyUpdate) =>
    api.put<ProjectLicensePolicyView>(`/projects/${id}/license-policy`, body).then((r) => r.data),

  deleteLicensePolicy: (id: number) =>
    api
      .delete<ProjectLicensePolicyView>(`/projects/${id}/license-policy`)
      .then((r) => r.data),
}

export const globalLicensePolicyApi = {
  get: () =>
    api.get<GlobalLicensePolicyView>('/policy/licenses').then((r) => r.data),

  put: (body: GlobalLicensePolicyUpdate) =>
    api.put<GlobalLicensePolicyView>('/policy/licenses', body).then((r) => r.data),

  /** Reverts to the YAML fallback (source becomes "config"). */
  reset: () =>
    api.delete<GlobalLicensePolicyView>('/policy/licenses').then((r) => r.data),
}

export const artifactLicensesApi = {
  get: (id: string) =>
    api.get<ArtifactLicenses>(`/artifacts/${encodeURIComponent(id)}/licenses`).then((r) => r.data),
}
