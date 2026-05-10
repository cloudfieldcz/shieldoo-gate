package alert

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// AlertPayload is sent to webhook/Slack/email.
// NEVER contains ClientIP, UserAgent, or raw MetadataJSON.
type AlertPayload struct {
	EventType  string    `json:"event_type"`
	ArtifactID string    `json:"artifact_id"`
	Reason     string    `json:"reason"`
	Timestamp  time.Time `json:"timestamp"`
	Metadata   any       `json:"metadata,omitempty"`
	// Structured vuln-scan extension columns. Always emitted as pointers so
	// renderers can distinguish "absent" from "zero" — anomaly rows legitimately
	// reference component_id=0 in tests, and we don't want to render that.
	ComponentID *int64 `json:"component_id,omitempty"`
	ScanRunID   *int64 `json:"scan_run_id,omitempty"`
	IgnoreID    *int64 `json:"ignore_id,omitempty"`
}

// NewAlertPayload converts an AuditEntry to AlertPayload, stripping
// ClientIP, UserAgent, and raw MetadataJSON. If MetadataJSON is valid JSON,
// it is parsed into the Metadata field as a structured value.
func NewAlertPayload(entry model.AuditEntry) AlertPayload {
	p := AlertPayload{
		EventType:   string(entry.EventType),
		ArtifactID:  entry.ArtifactID,
		Reason:      entry.Reason,
		Timestamp:   entry.Timestamp,
		ComponentID: entry.ComponentID,
		ScanRunID:   entry.ScanRunID,
		IgnoreID:    entry.IgnoreID,
	}

	if entry.MetadataJSON != "" {
		var meta map[string]any
		if err := json.Unmarshal([]byte(entry.MetadataJSON), &meta); err == nil {
			p.Metadata = meta
		}
	}

	return p
}

// EventTitle returns a human-readable header for the event type, used by
// channel renderers (Slack header block, email subject augmentation). The
// vuln-scan event types get curated titles; legacy proxy events keep their
// existing wording so existing dashboards don't churn.
func EventTitle(eventType string) string {
	switch eventType {
	// Proxy / artifact lifecycle (existing):
	case string(model.EventBlocked):
		return "Artifact Blocked"
	case string(model.EventQuarantined):
		return "Artifact Quarantined"
	case string(model.EventReleased):
		return "Artifact Released"
	case string(model.EventTagMutated):
		return "Tag Digest Changed"
	case string(model.EventRescanQueued):
		return "Rescan Queued"
	case string(model.EventOverrideCreated):
		return "Override Created"
	case string(model.EventOverrideRevoked):
		return "Override Revoked"
	// Vuln-scan additions:
	case string(model.EventScanNewCritical):
		return "New CRITICAL CVEs detected"
	case string(model.EventScanNewHigh):
		return "New HIGH CVEs detected"
	case string(model.EventScanAnomaly):
		return "Vulnerability anomaly (3σ spike)"
	case string(model.EventScanRunFailed):
		return "Scan run failed"
	case string(model.EventIgnoreCreated):
		return "CVE ignore created"
	case string(model.EventIgnoreRevoked):
		return "CVE ignore revoked"
	case string(model.EventIgnoreExpired), string(model.EventScanIgnoreExpired):
		return "CVE ignore expired"
	case string(model.EventSuperTokenUsed):
		return "Global super-token used"
	default:
		return "Security Event: " + eventType
	}
}

// EventDescription returns a one-line summary tailored to the event type.
// Used by email digest rendering — falls back to the raw Reason for events
// that don't have a curated template.
func EventDescription(p AlertPayload) string {
	switch p.EventType {
	case string(model.EventScanNewCritical), string(model.EventScanNewHigh),
		string(model.EventScanAnomaly), string(model.EventScanRunFailed):
		// These events carry the human summary in Reason and reference a
		// specific (component_id, scan_run_id). Surface them inline.
		var b strings.Builder
		b.WriteString(p.Reason)
		if p.ComponentID != nil && *p.ComponentID > 0 {
			fmt.Fprintf(&b, " — component=%d", *p.ComponentID)
		}
		if p.ScanRunID != nil && *p.ScanRunID > 0 {
			fmt.Fprintf(&b, ", scan_run=%d", *p.ScanRunID)
		}
		return b.String()
	case string(model.EventIgnoreExpired), string(model.EventScanIgnoreExpired),
		string(model.EventIgnoreCreated), string(model.EventIgnoreRevoked):
		var b strings.Builder
		b.WriteString(p.Reason)
		if p.IgnoreID != nil && *p.IgnoreID > 0 {
			fmt.Fprintf(&b, " — ignore=%d", *p.IgnoreID)
		}
		if p.ComponentID != nil && *p.ComponentID > 0 {
			fmt.Fprintf(&b, ", component=%d", *p.ComponentID)
		}
		return b.String()
	default:
		return p.Reason
	}
}
