# Compliance Reporting Dashboard

> Automated compliance evidence generation for SOC 2, ISO 27001, NIST SSDF, and EU Cyber Resilience Act.

**Status:** Proposed
**Priority:** Medium-High
**Perspective:** CISO / Governance, Risk & Compliance (GRC)

## Problem

Security teams deploying Shieldoo Gate often need to demonstrate to auditors and regulators that their software supply chain is protected. Today, this requires manually querying the audit log, exporting data, and assembling evidence. There is no built-in way to generate compliance-ready reports that map Shieldoo Gate's controls to specific regulatory frameworks.

Relevant regulations and standards that require supply chain security controls:

- **NIST SSDF** (Secure Software Development Framework) — PS.1, PS.2, PS.3 (third-party software verification)
- **SOC 2 Type II** — CC6.1, CC7.1, CC7.2 (logical access, system monitoring, change detection)
- **ISO 27001:2022** — A.8.28 (secure coding), A.5.21 (supply chain security)
- **EU Cyber Resilience Act** — Article 13 (vulnerability handling), Annex I (security requirements)
- **US Executive Order 14028** — Section 4 (software supply chain security, SBOM requirements)

## Proposed Solution

Add a reporting module that generates compliance-ready evidence from Shieldoo Gate's existing data (audit log, scan results, policy configuration, SBOM).

### Report Types

1. **Executive Summary** — High-level metrics for management: total artifacts scanned, blocked, quarantined, scanner coverage, policy mode, top threats. Weekly/monthly cadence.
2. **Compliance Evidence Report** — Maps Shieldoo Gate controls to specific framework requirements. Shows which controls are active, evidence from audit logs, and any gaps. Suitable for auditor review.
3. **Threat Intelligence Summary** — Detailed breakdown of detected threats: attack types, ecosystems affected, response times, false positive rates. Useful for security operations review.
4. **Artifact Inventory Report** — Full inventory of all cached artifacts with scan status, provenance (if available), license info (if license policy enabled), and SBOM references.
5. **Vulnerability SLA Report** — Tracks time from vulnerability discovery to remediation (quarantine, override, or version upgrade). Measures compliance with organizational SLA targets.

### Framework Mappings

```
NIST SSDF PS.1 (Verify third-party components)
  → Evidence: Scan results for all artifacts, scanner configuration, threat feed status

NIST SSDF PS.3 (Verify integrity of components)
  → Evidence: Hash verification results, provenance checks (if enabled), tag mutability detection

SOC 2 CC7.1 (Monitoring)
  → Evidence: Alerting configuration, SIEM integration, audit log completeness

ISO 27001 A.5.21 (ICT supply chain security)
  → Evidence: Policy mode, override history, quarantine actions, response times

EU CRA Article 13 (Vulnerability handling)
  → Evidence: Vulnerability scan results (Trivy/OSV), remediation timeline, SBOM availability
```

### Key Requirements

1. **Scheduled generation:** Reports can be generated on schedule (daily, weekly, monthly) and delivered via email or stored in the cache for download.
2. **Export formats:** PDF (for auditors), HTML (for internal review), JSON (for GRC tool integration), CSV (for custom analysis).
3. **Date range selection:** All reports accept a date range parameter. Default to the last 30 days.
4. **Customizable branding:** Allow organization name, logo, and custom footer for professional-looking audit evidence.
5. **Data retention awareness:** Reports should note the audit log retention period and warn if the requested date range exceeds available data.

### Configuration

```yaml
reporting:
  enabled: false
  schedule: "0 6 * * MON"            # Every Monday at 06:00 (cron syntax)
  formats: ["pdf", "html"]
  frameworks: ["nist-ssdf", "soc2", "iso27001"]
  retention_days: 365                 # Keep generated reports for 1 year
  branding:
    organization: "Acme Corp"
    logo_path: ""                     # Optional path to logo image
  delivery:
    email:
      enabled: false
      to: ["security@example.com", "ciso@example.com"]
    store:
      enabled: true                   # Store in cache for API/UI download
```

### How It Fits Into the Architecture

- **New module:** `internal/reporting/` with report generators per type and framework formatters.
- **Admin API:** New endpoints:
  - `POST /api/v1/reports/generate` — trigger on-demand report generation
  - `GET /api/v1/reports` — list generated reports
  - `GET /api/v1/reports/{id}/download` — download a report
- **Admin UI:** New "Reports" section with report generation controls, history, and download links.
- **Dependencies:** Requires existing audit log, scan results, and optionally SBOM data (for full compliance coverage).
- **Scheduler:** Extend the existing rescan scheduler or add a dedicated report scheduler.

### Considerations

- **Data completeness:** Compliance reports are only as good as the underlying data. Reports should clearly indicate which controls are active and which are not configured.
- **Audit log immutability:** The append-only audit log is a strong foundation for compliance evidence. Reports should reference specific audit log entries.
- **Performance:** Report generation for large date ranges can be expensive. Generate asynchronously and notify via existing alert channels.
- **Legal disclaimer:** Reports are evidence aids, not legal compliance certifications. Include appropriate disclaimers.
