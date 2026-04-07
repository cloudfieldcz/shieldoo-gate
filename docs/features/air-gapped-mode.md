# Air-Gapped / Offline Mode

> Full offline operation for classified, regulated, and network-restricted environments where external connectivity is not available.

**Status:** Proposed
**Priority:** Medium
**Perspective:** CISO / Defense & Regulated Industries

## Problem

Many high-security environments — defense contractors, government agencies, financial institutions, healthcare, critical infrastructure — operate air-gapped networks with no internet access. These organizations are *especially* vulnerable to supply chain attacks because:

1. They cannot use cloud-based scanning services (OSV API, Sigstore, upstream threat feeds).
2. Package ingestion is a manual process (carried in on approved media), which is error-prone and often lacks automated scanning.
3. Once a compromised package enters the air-gapped environment, there is no external threat intelligence to catch it retroactively.

Shieldoo Gate currently assumes internet connectivity for upstream registry proxying, threat feed refresh, OSV API queries, and AI scanner (Azure OpenAI / OpenAI API). An air-gapped deployment requires all of these to work with local data.

## Proposed Solution

Add an air-gapped deployment mode where all external dependencies are replaced with local equivalents. The system operates as a curated package repository rather than a transparent proxy.

### Operational Model

```
External Network (staging)          Air-Gapped Network (production)
┌─────────────────────────┐         ┌──────────────────────────────┐
│                         │         │                              │
│  Shieldoo Gate          │  export │  Shieldoo Gate               │
│  (full proxy mode)      │ ──────► │  (air-gapped mode)           │
│                         │  media  │                              │
│  - Scans everything     │         │  - Serves pre-scanned only   │
│  - Fetches threat feed  │         │  - Local threat feed DB      │
│  - Queries OSV API      │         │  - Local vulnerability DB    │
│  - AI scanner active    │         │  - Built-in scanners only    │
│                         │         │                              │
└─────────────────────────┘         └──────────────────────────────┘
```

### Key Components

1. **Export/Import mechanism:** A staging Shieldoo Gate instance (with internet) scans and approves packages. An export command produces a signed, tamper-evident bundle containing:
   - Cached artifacts (only CLEAN-status packages)
   - Scan results and SBOM data
   - Threat feed snapshot
   - Trivy vulnerability database snapshot
   - Bundle manifest with SHA-256 checksums and ed25519 signature

2. **Local threat feed:** Instead of fetching from `feed.shieldoo.io`, load from a local file or database populated via the import mechanism. Periodic refresh replaced by manual import.

3. **Local vulnerability database:** Bundle the Trivy vulnerability DB and OSV data as a local snapshot. Trivy already supports `--skip-db-update` with a pre-downloaded DB.

4. **Curated repository mode:** In air-gapped mode, the proxy does not forward requests to upstream registries. It only serves packages that were explicitly imported and approved. Unknown packages return 404 (not a proxy error, but "package not available in this environment").

5. **Bundle signing:** Export bundles are cryptographically signed (ed25519). The air-gapped instance verifies the signature before import. Key management via config.

### CLI Commands

```bash
# On the staging instance (internet-connected)
shieldoo export \
  --ecosystems pypi,npm,docker \
  --status clean \
  --since 2026-03-01 \
  --sign-key /path/to/signing-key \
  --output /media/shieldoo-export-2026-04.sgb

# On the air-gapped instance
shieldoo import \
  --verify-key /path/to/verify-key \
  --bundle /media/shieldoo-export-2026-04.sgb \
  --dry-run                              # Preview what would be imported

shieldoo import \
  --verify-key /path/to/verify-key \
  --bundle /media/shieldoo-export-2026-04.sgb
```

### Configuration

```yaml
server:
  mode: "air-gapped"                     # "proxy" (default) | "air-gapped"

air_gapped:
  verify_key: "/etc/shieldoo/verify.pub"  # ed25519 public key for bundle verification
  reject_unsigned: true                    # Reject unsigned import bundles
  allow_manual_add: false                  # Allow adding individual packages via API
  vulnerability_db:
    trivy_db_path: "/var/lib/shieldoo/trivy-db"
    osv_snapshot_path: "/var/lib/shieldoo/osv-snapshot"
  threat_feed:
    snapshot_path: "/var/lib/shieldoo/threat-feed-snapshot.json"
```

### How It Fits Into the Architecture

- **Config:** New `server.mode` field. When `air-gapped`, all upstream HTTP clients are disabled, threat feed client points to local file, OSV scanner uses local snapshot.
- **New module:** `internal/airgap/` with export/import logic, bundle format, signing/verification.
- **CLI:** New `export` and `import` subcommands in the `shieldoo` CLI (or `shieldoo-gate` binary).
- **Adapters:** In air-gapped mode, adapters serve from cache only. `fetchFromUpstream()` returns a clear error indicating the package is not available.
- **Scanner:** External scanners (GuardDog bridge, AI scanner) are disabled in air-gapped mode. Built-in scanners + Trivy (with local DB) remain active.

### Considerations

- **Freshness vs. security:** Air-gapped vulnerability databases become stale. The UI should prominently display the age of the last import and warn when the vulnerability DB is older than a configurable threshold (e.g., 30 days).
- **Bundle size:** A full export can be large (tens of GB for Docker images). Support incremental exports (only new/changed artifacts since last export).
- **Compliance:** Air-gapped deployments are common in environments subject to NIST 800-171, FedRAMP, ITAR, and similar standards. The export bundle's cryptographic integrity verification and chain-of-custody logging directly support these requirements.
- **Testing:** E2E tests for air-gapped mode need to simulate the full export→transfer→import cycle without network access.
