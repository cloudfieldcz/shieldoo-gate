package model

import "time"

type EventType string

const (
	EventServed          EventType = "SERVED"
	EventBlocked         EventType = "BLOCKED"
	EventQuarantined     EventType = "QUARANTINED"
	EventReleased        EventType = "RELEASED"
	EventScanned         EventType = "SCANNED"
	EventOverrideCreated EventType = "OVERRIDE_CREATED"
	EventOverrideRevoked EventType = "OVERRIDE_REVOKED"
)

type AuditEntry struct {
	ID           int64     `db:"id" json:"id"`
	Timestamp    time.Time `db:"ts" json:"ts"`
	EventType    EventType `db:"event_type" json:"event_type"`
	ArtifactID   string    `db:"artifact_id" json:"artifact_id,omitempty"`
	ClientIP     string    `db:"client_ip" json:"client_ip,omitempty"`
	UserAgent    string    `db:"user_agent" json:"user_agent,omitempty"`
	Reason       string    `db:"reason" json:"reason,omitempty"`
	MetadataJSON string    `db:"metadata_json" json:"metadata_json,omitempty"`
}
