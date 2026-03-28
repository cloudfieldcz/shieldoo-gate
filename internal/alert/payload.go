package alert

import (
	"encoding/json"
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
}

// NewAlertPayload converts an AuditEntry to AlertPayload, stripping
// ClientIP, UserAgent, and raw MetadataJSON. If MetadataJSON is valid JSON,
// it is parsed into the Metadata field as a structured value.
func NewAlertPayload(entry model.AuditEntry) AlertPayload {
	p := AlertPayload{
		EventType:  string(entry.EventType),
		ArtifactID: entry.ArtifactID,
		Reason:     entry.Reason,
		Timestamp:  entry.Timestamp,
	}

	if entry.MetadataJSON != "" {
		var meta map[string]any
		if err := json.Unmarshal([]byte(entry.MetadataJSON), &meta); err == nil {
			p.Metadata = meta
		}
	}

	return p
}
