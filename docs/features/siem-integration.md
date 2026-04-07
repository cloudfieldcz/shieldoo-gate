# SIEM Integration

> Native integration with enterprise SIEM platforms (Splunk, Elastic/ELK, Sentinel, etc.) for centralized security monitoring.

**Status:** Planned (v1.2+)
**Origin:** Initial analysis roadmap, section 15

## Problem

Enterprise security teams use SIEM (Security Information and Event Management) platforms as their central monitoring hub. While Shieldoo Gate already supports webhook alerts and structured JSON logging, integrating with SIEMs currently requires custom webhook receivers or log forwarders. Native SIEM integration would reduce deployment friction in enterprise environments.

## Proposed Solution

Provide pre-built integrations for major SIEM platforms that go beyond raw webhook delivery — including proper event formatting, field mapping, and correlation support.

### Key Requirements

1. **Supported platforms:**
   - **Splunk** — via Splunk HEC (HTTP Event Collector)
   - **Elastic/ELK** — via Elasticsearch ingest API or Logstash HTTP input
   - **Microsoft Sentinel** — via Log Analytics Data Collector API
   - **Generic Syslog** — via RFC 5424 syslog over TCP/TLS (covers QRadar, ArcSight, etc.)

2. **Event format:** Each SIEM has its own preferred event schema:
   - **Splunk:** JSON events with `sourcetype=shieldoo:gate` and CIM-compliant field names
   - **Elastic:** ECS (Elastic Common Schema) formatted events
   - **Sentinel:** Custom log type with Azure-expected field naming
   - **Syslog:** CEF (Common Event Format) messages

3. **Configuration:**
   ```yaml
   alerts:
     siem:
       enabled: false
       platform: "splunk"          # "splunk" | "elastic" | "sentinel" | "syslog"
       splunk:
         hec_url: ""               # e.g., "https://splunk.example.com:8088/services/collector"
         token_env: "SPLUNK_HEC_TOKEN"
         index: "security"
         sourcetype: "shieldoo:gate"
       elastic:
         url: ""                   # e.g., "https://elastic.example.com:9200"
         index: "shieldoo-gate"
         api_key_env: "ELASTIC_API_KEY"
       sentinel:
         workspace_id: ""
         shared_key_env: "SENTINEL_SHARED_KEY"
         log_type: "ShieldooGate"
       syslog:
         host: ""
         port: 514
         protocol: "tcp"           # "tcp" | "udp" | "tls"
         facility: "local0"
       on: ["BLOCKED", "QUARANTINED", "TAG_MUTATED"]
   ```

4. **Correlation fields:** Include fields that enable SIEM correlation:
   - `client_ip` — correlate with network logs
   - `user_agent` — identify affected CI/CD pipelines
   - `artifact_id` — correlate across multiple events for the same package
   - `timestamp` in ISO 8601

5. **Retry and buffering:** SIEM endpoints can be temporarily unavailable. Implement:
   - Configurable retry with exponential backoff
   - In-memory buffer (bounded) for events during SIEM outage
   - Dropped event counter metric

### How It Fits Into the Architecture

- **Alerter:** Add new `SIEMDispatcher` alongside existing `WebhookDispatcher`, `SlackDispatcher`, and `EmailDispatcher` in `internal/alert/`. It follows the same `Alerter` interface and event filtering pattern.
- **Configuration:** New `alerts.siem` section in `config.yaml` with per-platform sub-configs.
- **Metrics:** Add `shieldoo_gate_siem_events_total{platform, status}` and `shieldoo_gate_siem_dropped_total{platform}` Prometheus counters.

### Considerations

- **Existing webhook as alternative:** Many SIEMs can already receive events via the existing webhook alert channel. The native integration adds value through proper schema formatting, field mapping, and platform-specific features (like Splunk HEC tokens or Sentinel custom log types).
- **Log forwarding alternative:** Organizations running Shieldoo Gate in Kubernetes often already have log forwarders (Fluentd, Fluent Bit, Filebeat) that can ship the structured JSON logs directly to their SIEM. Native integration is most valuable for Docker Compose / bare-metal deployments without existing log infrastructure.
- **Volume:** In high-traffic environments, SIEM event volume can be significant. The `on` filter and batch/buffering settings help control this.
