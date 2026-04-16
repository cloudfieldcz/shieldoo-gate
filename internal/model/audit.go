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
	EventTagMutated      EventType = "TAG_MUTATED"
	EventRescanQueued       EventType = "RESCAN_QUEUED"
	EventAllowedWithWarning EventType = "ALLOWED_WITH_WARNING"
	EventIntegrityViolation EventType = "INTEGRITY_VIOLATION"
	EventArtifactDeleted    EventType = "ARTIFACT_DELETED"
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
	UserEmail    string    `db:"user_email" json:"user_email,omitempty"`
	ProjectID    *int64    `db:"project_id" json:"project_id,omitempty"`
}

// License policy + project-related event types (v1.2).
const (
	EventLicenseBlocked      EventType = "LICENSE_BLOCKED"
	EventLicenseWarned       EventType = "LICENSE_WARNED"
	EventLicenseCheckSkipped EventType = "LICENSE_CHECK_SKIPPED"
	EventProjectNotFound     EventType = "PROJECT_NOT_FOUND"
	EventSBOMGenerated       EventType = "SBOM_GENERATED"
)
