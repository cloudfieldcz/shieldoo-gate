import type { Severity } from '../../api/vulnerabilities'

/** Sort weight, most-important first (CRITICAL → INFO). Lower sorts earlier. */
export const severityRank: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  UNKNOWN: 4,
  INFO: 5,
}
