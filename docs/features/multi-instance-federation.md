# Multi-Instance Federation

> Synchronize threat intelligence, scan results, and policy decisions across multiple Shieldoo Gate instances deployed in different environments, regions, or organizations.

**Status:** Proposed
**Priority:** Medium
**Perspective:** Platform Engineering / Enterprise Architecture

## Problem

Large organizations often need multiple Shieldoo Gate instances:

- **Multi-region:** One instance per datacenter or cloud region for latency and availability.
- **Environment separation:** Separate instances for development, staging, and production (different policy modes).
- **Multi-team:** Different business units with distinct registries and policies but shared threat intelligence.
- **Hybrid cloud:** On-premises + cloud instances that need to share security data.

Currently, each instance operates independently. A malicious package detected by one instance must be manually blocked on all others. Threat intelligence, scan results, and policy overrides do not propagate automatically.

## Proposed Solution

Implement a federation protocol that allows Shieldoo Gate instances to form a cluster and share security-relevant data.

### Federation Model

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│  Instance A    │    │  Instance B    │    │  Instance C    │
│  (EU region)   │◄──►│  (US region)   │◄──►│  (dev/staging) │
│                │    │                │    │                │
│  Policy: strict│    │  Policy: strict│    │  Policy: balanced│
│  Ecosystems:   │    │  Ecosystems:   │    │  Ecosystems:   │
│  PyPI, npm     │    │  PyPI, Docker  │    │  all           │
└────────────────┘    └────────────────┘    └────────────────┘
         │                    │                      │
         └────────────────────┴──────────────────────┘
                    Shared via Federation:
                    • Threat detections
                    • Scan results (verdicts)
                    • Policy overrides
                    • Threat feed additions
```

### Shared Data Categories

1. **Threat detections (always shared):** When any instance detects a MALICIOUS artifact (high confidence), the detection propagates to all federated instances. Receiving instances immediately quarantine the artifact if cached.
2. **Scan results (configurable):** Share scan verdicts and findings so other instances can benefit from already-completed scans. Reduces redundant scanning of the same artifact.
3. **Policy overrides (configurable):** Share allowlists and blocklists across instances. Optional — some organizations want per-instance overrides.
4. **Threat feed contributions:** Locally detected threats auto-submitted to a shared internal feed (precursor to the public threat feed portal).

### Synchronization Protocol

- **Transport:** Mutual TLS (mTLS) over HTTPS. Each instance has a client certificate for authentication.
- **Topology:** Mesh (every instance connects to every other) or hub-spoke (one primary, others subscribe).
- **Consistency:** Eventual consistency. Detections propagate within configurable interval (default: 30 seconds). No distributed transactions.
- **Conflict resolution:** For overrides, last-writer-wins with instance priority. For detections, union (most restrictive verdict wins).
- **Deduplication:** Artifacts identified by ecosystem + name + version + SHA-256. Duplicate detections are merged.

### Configuration

```yaml
federation:
  enabled: false
  instance_id: "eu-prod-01"            # Unique instance identifier
  topology: "mesh"                      # "mesh" | "hub" | "spoke"
  peers:
    - url: "https://gate-us.example.com:8443"
      name: "us-prod-01"
    - url: "https://gate-dev.example.com:8443"
      name: "dev-01"
  tls:
    cert: "/etc/shieldoo/federation.crt"
    key: "/etc/shieldoo/federation.key"
    ca: "/etc/shieldoo/federation-ca.crt"
  sync:
    interval: "30s"
    share_scan_results: true
    share_overrides: false              # Per-instance overrides
    share_detections: true              # Always recommended
  filters:
    min_confidence: 0.8                 # Only share high-confidence detections
    ecosystems: []                      # Empty = all ecosystems
```

### How It Fits Into the Architecture

- **New module:** `internal/federation/` with peer management, sync protocol, conflict resolution.
- **Admin API:** New endpoints:
  - `GET /api/v1/federation/status` — peer connectivity, sync status, last sync time
  - `GET /api/v1/federation/peers` — list configured peers
  - `POST /api/v1/federation/sync` — trigger manual sync
- **Database:** New `federation_events` table for tracking received/sent events. New `federation_peers` table for peer metadata.
- **Metrics:** `shieldoo_gate_federation_events_sent_total`, `shieldoo_gate_federation_events_received_total`, `shieldoo_gate_federation_sync_latency_seconds`.

### Considerations

- **Network partitions:** When a peer is unreachable, buffer events locally and replay when connectivity is restored. Bounded buffer to prevent memory issues.
- **Trust model:** Federation implies trust between instances. A compromised instance could inject false detections (denial-of-service via false MALICIOUS verdicts). Consider requiring minimum confidence thresholds and allowing manual review of federated detections.
- **Bandwidth:** Scan result sharing can generate significant traffic in high-volume environments. Consider sharing only verdicts (not full findings) by default.
- **Privacy:** In multi-organization federation, only share threat indicators (hashes, verdicts), not artifact content or internal metadata.
- **Ordering:** Use logical timestamps (Lamport clocks) or vector clocks for correct event ordering across instances.
