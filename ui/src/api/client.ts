import axios from 'axios'
import type {
  ArtifactWithStatus,
  ArtifactDetail,
  AuditEntry,
  PolicyOverride,
  StatsSummary,
  HealthStatus,
  PaginatedResponse,
  DockerRepository,
  DockerTag,
  DockerRegistry,
} from './types'

const api = axios.create({
  baseURL: '/api/v1',
})

export const artifactsApi = {
  list: (page = 1, perPage = 50, ecosystem?: string, status?: string) =>
    api
      .get<PaginatedResponse<ArtifactWithStatus>>('/artifacts', {
        params: { page, per_page: perPage, ecosystem, status },
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

  override: (id: string, data?: { reason?: string; scope?: string }) =>
    api.post(`/artifacts/${encodeURIComponent(id)}/override`, data ?? {}).then((r) => r.data),
}

export const statsApi = {
  summary: () => api.get<StatsSummary>('/stats/summary').then((r) => r.data),
  blocked: () => api.get<AuditEntry[]>('/stats/blocked').then((r) => r.data),
}

export const auditApi = {
  list: (page = 1, perPage = 50, eventType?: string) =>
    api
      .get<PaginatedResponse<AuditEntry>>('/audit', {
        params: { page, per_page: perPage, event_type: eventType },
      })
      .then((r) => r.data),
}

export const feedApi = {
  list: () => api.get('/feed').then((r) => r.data),
  refresh: () => api.post('/feed/refresh').then((r) => r.data),
}

export const overridesApi = {
  list: (page = 1, perPage = 50, active?: boolean) =>
    api
      .get<PaginatedResponse<PolicyOverride>>('/overrides', {
        params: { page, per_page: perPage, active: active ? 'true' : undefined },
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
