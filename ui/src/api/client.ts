import axios from 'axios'
import type {
  ArtifactWithStatus,
  ArtifactDetail,
  AuditEntry,
  StatsSummary,
  HealthStatus,
  PaginatedResponse,
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

export const healthApi = {
  check: () => api.get<HealthStatus>('/health').then((r) => r.data),
}
